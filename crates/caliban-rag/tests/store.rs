//! The document registry behaves the same in memory and on Postgres (`CALIBAN_TEST_DATABASE_URL`).

use caliban_nodes::journal::AuditEvent;
use caliban_rag::store::{
    CollectionRecord, CollectionSettings, DocFinding, DocQuery, DocRef, DocStatus, IndexOutcome, MemoryRagStore,
    NewDocument, RagStore, RagStoreError, Trust,
};
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;

fn collection(tenant: &str, name: &str) -> CollectionRecord {
    CollectionRecord {
        id: format!("ragc_{}", uuid::Uuid::now_v7().simple()),
        tenant_id: tenant.into(),
        name: name.into(),
        description: Some("handbooks".into()),
        embedding_model: "emb".into(),
        rerank_model: None,
        settings: CollectionSettings::default(),
        created_at: Utc::now(),
        created_by: "user:jo".into(),
        deleted_at: None,
        purged_at: None,
    }
}

fn doc(c: &CollectionRecord, id: &str, hash: &str) -> NewDocument {
    NewDocument {
        tenant_id: c.tenant_id.clone(),
        collection_id: c.id.clone(),
        doc_id: id.into(),
        doc_key: format!("key-{id}"),
        content_type: "text/markdown".into(),
        source: None,
        trust: Trust::Trusted,
        sealed_content: format!("sealed-{hash}"),
        content_hash: hash.into(),
        bytes: 10,
        valid_from: None,
        valid_to: None,
        created_by: "user:jo".into(),
    }
}

fn audit(id: &str) -> Option<AuditEvent> {
    Some(AuditEvent {
        id: id.into(),
        tenant_id: "acme".into(),
        actor: "user:jo".into(),
        action: "rag.document.ingest".into(),
        target: Some("x".into()),
        detail: serde_json::json!({"n": 1}),
        at: Utc::now(),
    })
}

fn ready() -> IndexOutcome {
    IndexOutcome::Ready { chunks: 2, tokens: 30, pii_entities: 1, findings: vec![] }
}

async fn suite(s: Arc<dyn RagStore>) {
    let lease = Duration::from_secs(30);
    let c = s.create_collection(collection("acme", "kb"), audit("a1")).await.unwrap();
    let dup = s.create_collection(collection("acme", "kb"), None).await.unwrap_err();
    assert!(matches!(dup, RagStoreError::Conflict(_)), "{dup:?}");
    s.create_collection(collection("globex", "kb"), None).await.unwrap();
    assert_eq!(s.collections("acme").await.unwrap().len(), 1);
    assert_eq!(s.collection("acme", "kb").await.unwrap().unwrap().id, c.id);

    // Versions, and the no-op on identical input.
    let (d1, created) = s.put_document(doc(&c, "a", "h1"), audit("a2")).await.unwrap();
    assert!(created && d1.version == 1 && d1.status == DocStatus::Pending);
    let (same, created) = s.put_document(doc(&c, "a", "h1"), None).await.unwrap();
    assert!(!created && same.version == 1);
    s.put_document(doc(&c, "b", "hb"), None).await.unwrap();

    // Claims are exclusive; the claim carries the sealed content.
    let (x, content) = s.claim("w1", lease).await.unwrap().unwrap();
    assert_eq!((x.doc_id.as_str(), content.as_str(), x.attempts), ("a", "sealed-h1", 1));
    let (y, _) = s.claim("w2", lease).await.unwrap().unwrap();
    assert_eq!(y.doc_id, "b");
    assert!(s.claim("w3", lease).await.unwrap().is_none());
    assert!(s.heartbeat(&x.key(), "w1", lease).await.unwrap());
    assert!(!s.heartbeat(&x.key(), "w2", lease).await.unwrap(), "only the lease holder renews");
    assert!(!s.finish(&x.key(), "w2", ready()).await.unwrap(), "only the lease holder finishes");

    // Not visible until ready.
    let refs = vec![("key-a".to_owned(), 1)];
    assert!(s.visible("acme", &c.id, &refs).await.unwrap().is_empty());
    assert!(s.finish(&x.key(), "w1", ready()).await.unwrap());
    assert_eq!(s.visible("acme", &c.id, &refs).await.unwrap().len(), 1);
    assert!(s.visible("globex", &c.id, &refs).await.unwrap().is_empty(), "per tenant");

    // A version 2 that becomes ready supersedes version 1 in one step.
    let (d2, _) = s.put_document(doc(&c, "a", "h2"), None).await.unwrap();
    assert_eq!(d2.version, 2);
    let page = s.documents("acme", &c.id, &DocQuery { limit: 10, ..DocQuery::default() }).await.unwrap();
    let a = page.iter().find(|p| p.latest.doc_id == "a").unwrap();
    assert_eq!((a.latest.version, a.live_version), (2, Some(1)));
    let (z, _) = s.claim("w1", lease).await.unwrap().unwrap();
    assert_eq!((z.doc_id.as_str(), z.version), ("a", 2));
    assert!(s.finish(&z.key(), "w1", ready()).await.unwrap());
    let versions = s.document("acme", &c.id, "a").await.unwrap();
    assert_eq!(
        versions.iter().map(|d| (d.version, d.status)).collect::<Vec<_>>(),
        vec![(2, DocStatus::Ready), (1, DocStatus::Superseded)]
    );
    assert_eq!(s.visible("acme", &c.id, &[("key-a".into(), 1), ("key-a".into(), 2)]).await.unwrap().len(), 1);
    let purge = s.purge_queue(10).await.unwrap();
    assert_eq!(purge.iter().map(|d| (d.doc_id.as_str(), d.version)).collect::<Vec<_>>(), vec![("a", 1)]);
    s.mark_purged(&purge[0].key()).await.unwrap();
    assert!(s.purge_queue(10).await.unwrap().is_empty());

    // Quarantine, then release; a release of anything else is a conflict.
    let q = IndexOutcome::Quarantined {
        chunks: 1,
        tokens: 5,
        pii_entities: 0,
        findings: vec![DocFinding { kind: "instruction".into(), chunk: 0, heading_path: vec!["FAQ".into()] }],
    };
    assert!(s.finish(&y.key(), "w2", q).await.unwrap());
    let yk = y.key();
    let rec = s.document("acme", &c.id, "b").await.unwrap().remove(0);
    assert_eq!((rec.status, rec.findings.len()), (DocStatus::Quarantined, 1));
    assert_eq!(rec.findings[0].heading_path, ["FAQ"], "the finding's headings are kept");
    let released = s.release(&yk, "user:jo", Utc::now(), audit("a3")).await.unwrap();
    assert!(released.findings_acknowledged && released.status == DocStatus::Pending);
    assert!(matches!(s.release(&yk, "user:jo", Utc::now(), None).await, Err(RagStoreError::Conflict(_))));
    let missing = DocRef { version: 9, ..yk.clone() };
    assert!(matches!(s.release(&missing, "user:jo", Utc::now(), None).await, Err(RagStoreError::NotFound(_))));

    // Retry: pending again, not claimable before its time.
    let (r, _) = s.claim("w1", lease).await.unwrap().unwrap();
    assert!(
        s.finish(&r.key(), "w1", IndexOutcome::Retry { error: "down".into(), after: Duration::from_secs(3600) })
            .await
            .unwrap()
    );
    assert!(s.claim("w1", lease).await.unwrap().is_none());
    let rec = s.document("acme", &c.id, "b").await.unwrap().remove(0);
    assert_eq!((rec.status, rec.error.as_deref()), (DocStatus::Pending, Some("down")));

    // An expired lease is taken over by another worker.
    s.put_document(doc(&c, "c", "hc"), None).await.unwrap();
    let (cc, _) = s.claim("w1", Duration::from_millis(1)).await.unwrap().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let taken = loop {
        if let Some((t, _)) = s.claim("w2", lease).await.unwrap() {
            break t;
        }
        assert!(std::time::Instant::now() < deadline, "the lease never expired");
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert_eq!((taken.doc_id.as_str(), taken.attempts), ("c", 2));
    assert!(!s.finish(&cc.key(), "w1", ready()).await.unwrap(), "the old holder lost it");
    assert!(s.finish(&taken.key(), "w2", IndexOutcome::Failed { error: "bad".into() }).await.unwrap());

    // Deletes are immediate and wipe the content.
    assert!(s.delete_document("acme", &c.id, "a", Utc::now(), audit("a4")).await.unwrap());
    assert!(!s.delete_document("acme", &c.id, "a", Utc::now(), None).await.unwrap());
    assert!(s.visible("acme", &c.id, &[("key-a".into(), 2)]).await.unwrap().is_empty());
    let listed = s.documents("acme", &c.id, &DocQuery { limit: 10, ..DocQuery::default() }).await.unwrap();
    assert!(listed.iter().all(|d| d.latest.doc_id != "a"));
    let failed = DocQuery { limit: 10, status: Some(DocStatus::Failed), ..DocQuery::default() };
    assert_eq!(s.documents("acme", &c.id, &failed).await.unwrap().len(), 1);
    let after = DocQuery { limit: 10, after: Some("b".into()), ..DocQuery::default() };
    let ids: Vec<String> =
        s.documents("acme", &c.id, &after).await.unwrap().iter().map(|d| d.latest.doc_id.clone()).collect();
    assert_eq!(ids, vec!["c"]);
    // Counts per status over each document's newest version; deleted documents are not counted.
    let counts = s.document_counts("acme").await.unwrap();
    let want: std::collections::BTreeMap<String, u64> = [("failed".into(), 1), ("pending".into(), 1)].into();
    assert_eq!(counts.get(&c.id), Some(&want), "{counts:?}");

    // The audit outbox: claimed once, gone once acknowledged.
    let events = s.claim_audit("cp", Duration::from_secs(60), 100).await.unwrap();
    let ids: Vec<String> = events.iter().map(|e| e.id.clone()).collect();
    for want in ["a1", "a2", "a3", "a4"] {
        assert!(ids.contains(&want.to_owned()), "{ids:?}");
    }
    assert!(s.claim_audit("cp2", Duration::from_secs(60), 100).await.unwrap().is_empty());
    s.ack_audit(&ids).await.unwrap();

    // Deleting the collection (and a tenant) deletes its documents; workers then drop the vectors.
    assert!(s.delete_collection("acme", "kb", Utc::now(), None).await.unwrap());
    assert!(s.collection("acme", "kb").await.unwrap().is_none());
    assert!(matches!(s.put_document(doc(&c, "d", "hd"), None).await, Err(RagStoreError::NotFound(_))));
    assert!(s.document("acme", &c.id, "b").await.unwrap().iter().all(|d| d.status == DocStatus::Deleted));
    let drop = s.collections_to_drop(10).await.unwrap();
    assert_eq!(drop.iter().map(|c| c.name.as_str()).collect::<Vec<_>>(), vec!["kb"]);
    s.mark_dropped("acme", &c.id, Utc::now()).await.unwrap();
    assert!(s.collections_to_drop(10).await.unwrap().is_empty());
    assert!(s.purge_queue(10).await.unwrap().is_empty());
    s.create_collection(collection("acme", "kb"), None).await.unwrap();
    assert_eq!(s.delete_tenant("globex", Utc::now()).await.unwrap(), 1);
    assert!(s.collections("globex").await.unwrap().is_empty());
}

#[tokio::test]
async fn memory_store() {
    suite(Arc::new(MemoryRagStore::new())).await;
}

#[tokio::test]
async fn postgres_store() {
    let Ok(url) = std::env::var("CALIBAN_TEST_DATABASE_URL") else { return };
    suite(Arc::new(caliban_rag::pg::PgRagStore::isolated(&url).await.unwrap())).await;
}
