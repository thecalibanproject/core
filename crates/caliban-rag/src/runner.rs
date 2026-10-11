//! The indexing loop on workers (and standalone processes): claim a pending document version,
//! index it under a renewed lease, record the outcome; and purge the vectors of deleted,
//! superseded and failed versions and of deleted collections.
//!
//! Untrusted documents have a vetting deadline (the collection's `vet_deadline_secs`): one whose
//! checks have not passed by then fails and stays invisible, rather than becoming visible later
//! when a backlog clears (fail closed; a verifier backlog let poisoned chunks through in
//! arXiv 2610.05826, preprint).

use crate::ingest::Indexer;
use crate::store::{CollectionRecord, DocumentRecord, IndexOutcome, RagStore, Trust};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

#[derive(Debug, Clone)]
pub struct IndexOptions {
    pub lease: Duration,
    pub heartbeat: Duration,
    /// How long an idle loop waits before it looks again.
    pub poll: Duration,
    /// Documents indexed at once by this process.
    pub concurrency: usize,
    /// How often the purge runs.
    pub purge_every: Duration,
}

impl Default for IndexOptions {
    fn default() -> Self {
        Self {
            lease: Duration::from_secs(60),
            heartbeat: Duration::from_secs(20),
            poll: Duration::from_millis(500),
            concurrency: 2,
            purge_every: Duration::from_secs(30),
        }
    }
}

pub struct IndexRunner {
    pub indexer: Arc<Indexer>,
    pub worker: String,
    pub opts: IndexOptions,
}

impl IndexRunner {
    pub fn new(indexer: Arc<Indexer>, worker: impl Into<String>, opts: IndexOptions) -> Arc<Self> {
        Arc::new(Self { indexer, worker: worker.into(), opts })
    }

    fn store(&self) -> &Arc<dyn RagStore> {
        &self.indexer.store
    }

    async fn collection_of(&self, d: &DocumentRecord) -> Option<CollectionRecord> {
        self.store().collections(&d.tenant_id).await.ok()?.into_iter().find(|c| c.id == d.collection_id)
    }

    /// Claims and indexes one document. `false`: there was nothing to do.
    pub async fn step(self: &Arc<Self>) -> bool {
        let claimed = match self.store().claim(&self.worker, self.opts.lease).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "rag: claiming a document failed");
                return false;
            }
        };
        let Some((doc, sealed)) = claimed else { return false };
        let key = doc.key();
        let outcome = match self.collection_of(&doc).await {
            None => IndexOutcome::Failed { error: "the collection is gone".into() },
            Some(c) if past_deadline_at(&doc, &c, chrono::Utc::now()) => IndexOutcome::Failed {
                error: format!(
                    "an untrusted document must pass its checks within {} s of ingest; it did not",
                    c.settings.vet_deadline_secs
                ),
            },
            Some(c) => {
                // Keep the lease while indexing.
                let stop = Arc::new(Notify::new());
                let beat = {
                    let (me, key, stop) = (Arc::clone(self), key.clone(), Arc::clone(&stop));
                    tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                () = stop.notified() => break,
                                () = tokio::time::sleep(me.opts.heartbeat) => {
                                    if !matches!(me.store().heartbeat(&key, &me.worker, me.opts.lease).await, Ok(true)) {
                                        break;
                                    }
                                }
                            }
                        }
                    })
                };
                let o = self.indexer.process(&doc, &sealed, &c).await;
                stop.notify_one();
                let _ = beat.await;
                o
            }
        };
        let what = match &outcome {
            IndexOutcome::Ready { .. } => "ready",
            IndexOutcome::Quarantined { .. } => "quarantined",
            IndexOutcome::Failed { .. } => "failed",
            IndexOutcome::Retry { .. } => "retry",
        };
        match self.store().finish(&key, &self.worker, outcome).await {
            Ok(true) => tracing::info!(
                tenant = %key.tenant_id, collection = %key.collection_id, doc = %key.doc_id, version = key.version,
                outcome = what, "rag: document indexed"
            ),
            Ok(false) => {
                tracing::info!(doc = %key.doc_id, "rag: the document changed while it was indexed; outcome dropped");
                self.clean_up_after(&doc).await;
            }
            Err(e) => tracing::warn!(error = %e, doc = %key.doc_id, "rag: recording the outcome failed"),
        }
        true
    }

    /// A version deleted while it was being indexed: points written after the purge looked would
    /// stay behind (never served: the registry says deleted). Another worker that took over an
    /// expired lease is left alone.
    async fn clean_up_after(&self, doc: &DocumentRecord) {
        let Ok(versions) = self.store().document(&doc.tenant_id, &doc.collection_id, &doc.doc_id).await else {
            return;
        };
        let gone = versions
            .iter()
            .find(|d| d.version == doc.version)
            .is_none_or(|d| matches!(d.status, crate::store::DocStatus::Deleted));
        if !gone {
            return;
        }
        if let Some(c) = self.collection_of(doc).await {
            let name = c.index_name(&self.indexer.prefix);
            if let Err(e) = self.indexer.index.delete_doc(&name, &doc.doc_key, Some(doc.version)).await {
                tracing::warn!(error = %e, doc = %doc.doc_id, "rag: cleaning up a deleted document failed");
            }
        }
    }

    /// Deletes vectors that are no longer served. Returns how many versions and collections it
    /// cleaned.
    pub async fn purge(&self) -> usize {
        let mut n = 0;
        if let Ok(cols) = self.store().collections_to_drop(16).await {
            for c in cols {
                let name = c.index_name(&self.indexer.prefix);
                match self.indexer.index.drop_collection(&name).await {
                    Ok(()) => {
                        let _ = self.store().mark_dropped(&c.tenant_id, &c.id, chrono::Utc::now()).await;
                        n += 1;
                    }
                    Err(e) => tracing::warn!(error = %e, collection = %c.id, "rag: dropping a collection failed"),
                }
            }
        }
        if let Ok(docs) = self.store().purge_queue(64).await {
            let mut by_collection: std::collections::HashMap<String, Option<CollectionRecord>> = Default::default();
            for d in docs {
                if !by_collection.contains_key(&d.collection_id) {
                    let c = self.collection_of(&d).await;
                    by_collection.insert(d.collection_id.clone(), c);
                }
                let Some(Some(c)) = by_collection.get(&d.collection_id) else { continue };
                let name = c.index_name(&self.indexer.prefix);
                match self.indexer.index.delete_doc(&name, &d.doc_key, Some(d.version)).await {
                    Ok(()) => {
                        let _ = self.store().mark_purged(&d.key()).await;
                        n += 1;
                    }
                    Err(e) => tracing::warn!(error = %e, doc = %d.doc_id, "rag: purging a document failed"),
                }
            }
        }
        n
    }

    /// Runs until `stop` is notified (`notify_waiters`): `concurrency` indexing loops, and the
    /// purge. A loop that finds nothing waits `poll` before it looks again.
    pub async fn run_loop(self: Arc<Self>, stop: Arc<Notify>) {
        let mut tasks = Vec::new();
        for _ in 0..self.opts.concurrency.max(1) {
            let (me, stop) = (Arc::clone(&self), Arc::clone(&stop));
            tasks.push(tokio::spawn(async move {
                let stopped = stop.notified();
                tokio::pin!(stopped);
                stopped.as_mut().enable();
                loop {
                    tokio::select! {
                        () = &mut stopped => break,
                        found = me.step() => {
                            if !found {
                                tokio::select! {
                                    () = &mut stopped => break,
                                    () = tokio::time::sleep(me.opts.poll) => {}
                                }
                            }
                        }
                    }
                }
            }));
        }
        let stopped = stop.notified();
        tokio::pin!(stopped);
        stopped.as_mut().enable();
        loop {
            self.purge().await;
            tokio::select! {
                () = &mut stopped => break,
                () = tokio::time::sleep(self.opts.purge_every) => {}
            }
        }
        for t in tasks {
            let _ = t.await;
        }
    }
}

/// Whether an untrusted document has missed its vetting deadline at `now`.
pub fn past_deadline_at(d: &DocumentRecord, c: &CollectionRecord, now: chrono::DateTime<chrono::Utc>) -> bool {
    let deadline = chrono::Duration::seconds(i64::try_from(c.settings.vet_deadline_secs).unwrap_or(i64::MAX));
    d.trust == Trust::Untrusted && now > d.created_at + deadline
}
