//! Tenant offboarding on the data plane: when the live config snapshot drops a tenant, its T2
//! semantic-cache entries are deleted from the vector store.
//!
//! Why the data plane: the control plane does not hold a `SemanticCache` (in split mode it never
//! sees the vector store, and `CALIBAN_QDRANT_URL` is a data-plane setting), and the in-memory
//! store lives inside each router. Every router already learns about a delete the same way, from
//! its next snapshot: standalone mode shares the `ConfigHandle` with the control plane, which
//! publishes the post-delete state into it; split-mode routers swap in the signed snapshot on their
//! next poll. So each router watches its own handle, and when a tenant id disappears it purges that
//! tenant from every collection of its cache (`SemanticCache::purge_tenant_everywhere`).
//!
//! - **Idempotent:** with Qdrant every router purges the same tenant; deleting entries that are
//!   already gone is a no-op.
//! - **Retried:** a failed purge (store unreachable) is retried on every tick until it succeeds.
//! - **Not resurrected:** tenant ids of deleted tenants cannot be reused on the control plane;
//!   should an id come back in a later snapshot anyway (a config file edit), a pending purge for it
//!   is dropped.
//! - **Gap:** a purge is only triggered by a router that observes the snapshot transition. If no
//!   router is running when the tenant is deleted, its entries stay until they expire
//!   (`[cache.semantic] ttl_secs`).

use crate::Gateway;
use caliban_config::Snapshot;
use caliban_types::TenantId;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

/// How often the snapshot is checked for dropped tenants.
pub const PURGE_EVERY: Duration = Duration::from_secs(2);

/// Tenant ids present in `before` and absent from `after`.
pub fn dropped_tenants(before: &Snapshot, after: &Snapshot) -> Vec<TenantId> {
    before.config.tenants.iter().map(|t| &t.id).filter(|id| after.tenant(id).is_none()).cloned().collect()
}

/// Watches a gateway's config handle and purges dropped tenants (see the module docs).
pub struct TenantPurger {
    gw: Arc<Gateway>,
    seen: Arc<Snapshot>,
    pending: BTreeSet<TenantId>,
}

impl TenantPurger {
    /// Starts from the gateway's current snapshot: tenants missing from it now are not purged.
    pub fn new(gw: Arc<Gateway>) -> Self {
        let seen = gw.config.load();
        Self { gw, seen, pending: BTreeSet::new() }
    }

    /// Tenants whose purge has not succeeded yet.
    pub fn pending(&self) -> &BTreeSet<TenantId> {
        &self.pending
    }

    /// One check: picks up tenants dropped since the last snapshot seen, then purges every pending
    /// one. Returns the tenants purged by this call.
    pub async fn tick(&mut self) -> Vec<TenantId> {
        let current = self.gw.config.load();
        if !Arc::ptr_eq(&current, &self.seen) {
            self.pending.extend(dropped_tenants(&self.seen, &current));
            self.seen = current;
        }
        let seen = Arc::clone(&self.seen);
        self.pending.retain(|t| seen.tenant(t).is_none());
        let Some(cache) = self.gw.semantic.clone() else {
            self.pending.clear();
            return vec![];
        };
        let mut purged = Vec::new();
        for t in self.pending.clone() {
            match cache.purge_tenant_everywhere(t.as_str()).await {
                Ok(collections) => {
                    tracing::info!(tenant = %t, collections, "semantic cache: purged the entries of a tenant that left the snapshot");
                    self.pending.remove(&t);
                    purged.push(t);
                }
                Err(e) => tracing::warn!(tenant = %t, error = %e, "semantic cache: tenant purge failed; retrying"),
            }
        }
        purged
    }
}

impl Gateway {
    /// Runs a [`TenantPurger`] in the background, checking every `every`.
    pub fn spawn_tenant_purge(self: &Arc<Self>, every: Duration) -> tokio::task::JoinHandle<()> {
        let mut purger = TenantPurger::new(Arc::clone(self));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                purger.tick().await;
            }
        })
    }
}
