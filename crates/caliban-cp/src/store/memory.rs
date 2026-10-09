//! In-memory backend (dev/demo): state and audit chain live in the process.

use super::audit::{AuditEntry, now_micros};
use super::{Backend, Check, Mutation, State, StoreError};
use caliban_ontology::Ontology;
use parking_lot::Mutex;
use serde_json::json;

pub struct MemoryBackend {
    inner: Mutex<(State, Vec<AuditEntry>)>,
}

impl MemoryBackend {
    /// Starts from `seed` and records the seeding as audit row 1 (as the Postgres backend does).
    pub fn seeded(mut seed: State) -> Self {
        let entry = AuditEntry::next(None, "system", &seed_draft(&seed), now_micros());
        seed.audit_head = entry.seq;
        Self { inner: Mutex::new((seed, vec![entry])) }
    }

    pub fn state(&self) -> State {
        self.inner.lock().0.clone()
    }
}

pub(crate) fn seed_draft(st: &State) -> super::audit::AuditDraft {
    super::audit::AuditDraft {
        tenant_id: None,
        action: "store.seed",
        target: None,
        detail: json!({
            "source": "config file",
            "tenants": st.tenants.len(),
            "models": st.models.len(),
            "providers": st.shared_providers.len(),
        }),
    }
}

#[async_trait::async_trait]
impl Backend for MemoryBackend {
    fn name(&self) -> &'static str {
        "memory"
    }

    async fn load(&self) -> Result<State, StoreError> {
        Ok(self.state())
    }

    async fn head(&self) -> Result<u64, StoreError> {
        Ok(self.inner.lock().0.audit_head)
    }

    async fn apply(&self, actor: &str, m: &Mutation, check: Check<'_>) -> Result<State, StoreError> {
        let mut guard = self.inner.lock();
        let (committed, log) = &mut *guard;
        // Work on a copy: any error leaves the committed state untouched (= rollback).
        let mut st = committed.clone();
        let draft = m.audit(&st);
        apply_to(&mut st, m)?;
        check(&st).map_err(StoreError::Invalid)?;
        let entry = AuditEntry::next(log.last(), actor, &draft, now_micros());
        st.audit_head = entry.seq;
        log.push(entry);
        *committed = st.clone();
        Ok(st)
    }

    async fn audit(&self, limit: usize) -> Result<Vec<AuditEntry>, StoreError> {
        let g = self.inner.lock();
        Ok(g.1[g.1.len().saturating_sub(limit)..].to_vec())
    }
}

fn need_tenant(st: &State, id: &str) -> Result<(), StoreError> {
    if st.has_tenant(id) { Ok(()) } else { Err(StoreError::NotFound("tenant".into())) }
}

/// The in-memory meaning of each mutation. `postgres.rs` must match it (enforced by the parity
/// test suite).
pub(super) fn apply_to(st: &mut State, m: &Mutation) -> Result<(), StoreError> {
    match m {
        Mutation::CreateTenant(t) => {
            match st.tenant_record(&t.id) {
                Some(x) if x.is_active() => {
                    return Err(StoreError::Conflict(format!("tenant '{}' already exists", t.id)));
                }
                Some(_) => {
                    return Err(StoreError::Conflict(format!(
                        "tenant id '{}' belonged to a deleted tenant and cannot be reused",
                        t.id
                    )));
                }
                None => {}
            }
            st.tenants.push(t.clone());
        }
        Mutation::DeleteTenant { id, at } => {
            let t = st
                .tenants
                .iter_mut()
                .find(|t| &t.id == id && t.is_active())
                .ok_or_else(|| StoreError::NotFound("tenant".into()))?;
            t.status = super::TenantStatus::Deleted;
            t.deleted_at = Some(*at);
            for k in st.api_keys.iter_mut().filter(|k| &k.tenant_id == id && k.is_active()) {
                k.revoked_at = Some(*at);
            }
            // BYOK credentials and the tenant's DEK are destroyed, not kept: nothing can open
            // what was sealed under the DEK again (crypto-shredding).
            st.provider_keys.retain(|p| &p.tenant_id != id);
            st.deks.remove(id);
            st.routes.remove(id);
            for ds in st.datasources.iter_mut().filter(|d| &d.tenant_id == id && d.is_live()) {
                ds.deleted_at = Some(*at);
                ds.connection = json!({});
            }
            for n in st.nodes.iter_mut().filter(|n| &n.tenant_id == id && n.is_live()) {
                n.deleted_at = Some(*at);
            }
        }
        Mutation::UpdateTenant { id, pii_default, pii_surrogate_scope, semantic_cache } => {
            let t = st
                .tenants
                .iter_mut()
                .find(|t| &t.id == id && t.is_active())
                .ok_or_else(|| StoreError::NotFound("tenant".into()))?;
            if let Some(m) = pii_default {
                t.pii_default = *m;
            }
            if let Some(s) = pii_surrogate_scope {
                t.pii_surrogate_scope = *s;
            }
            if let Some(s) = semantic_cache {
                t.semantic_cache = *s;
            }
        }
        Mutation::CreateApiKey(k) => {
            need_tenant(st, &k.tenant_id)?;
            if st.api_keys.iter().any(|x| x.hash == k.hash || x.id == k.id) {
                return Err(StoreError::Conflict("api key already exists".into()));
            }
            st.api_keys.push(k.clone());
        }
        Mutation::RevokeApiKey { tenant_id, id, at } => {
            need_tenant(st, tenant_id)?;
            let k = st
                .api_keys
                .iter_mut()
                .find(|k| &k.tenant_id == tenant_id && &k.id == id && k.is_active())
                .ok_or_else(|| StoreError::NotFound("api key".into()))?;
            k.revoked_at = Some(*at);
        }
        Mutation::CreateProviderKey(p) => {
            need_tenant(st, &p.tenant_id)?;
            if st.provider_keys.iter().any(|x| x.tenant_id == p.tenant_id && x.id == p.id) {
                return Err(StoreError::Conflict(format!("provider '{}' already exists for this tenant", p.id)));
            }
            st.provider_keys.push(p.clone());
        }
        Mutation::DeleteProviderKey { tenant_id, id } => {
            let before = st.provider_keys.len();
            st.provider_keys.retain(|p| !(&p.tenant_id == tenant_id && &p.id == id));
            if st.provider_keys.len() == before {
                return Err(StoreError::NotFound("provider key".into()));
            }
        }
        Mutation::CreateModel(model) => {
            if st.models.iter().any(|x| x.id == model.id) {
                return Err(StoreError::Conflict(format!("model '{}' already exists", model.id)));
            }
            st.models.push(model.clone());
        }
        Mutation::DeleteModel(id) => {
            let pos = st
                .models
                .iter()
                .position(|x| x.id.as_str() == id)
                .ok_or_else(|| StoreError::NotFound("model".into()))?;
            st.models.remove(pos);
        }
        Mutation::CreateSharedProvider(p) => {
            if st.shared_providers.iter().any(|x| x.provider.id == p.provider.id) {
                return Err(StoreError::Conflict(format!("provider '{}' already exists", p.provider.id)));
            }
            st.shared_providers.push(p.clone());
        }
        Mutation::DeleteSharedProvider(id) => {
            let pos = st
                .shared_providers
                .iter()
                .position(|x| x.provider.id.as_str() == id)
                .ok_or_else(|| StoreError::NotFound("provider".into()))?;
            st.shared_providers.remove(pos);
        }
        Mutation::SetRoutes { tenant_id, routes } => {
            need_tenant(st, tenant_id)?;
            if routes.is_empty() {
                st.routes.remove(tenant_id);
            } else {
                st.routes.insert(tenant_id.clone(), routes.clone());
            }
        }
        Mutation::CreateDatasource(ds) => {
            need_tenant(st, &ds.tenant_id)?;
            if crate::keys::count_sealed(&ds.connection) > 0 && !st.deks.contains_key(&ds.tenant_id) {
                return Err(StoreError::Invalid(format!(
                    "datasource '{}' has secrets sealed under a tenant key that does not exist",
                    ds.name
                )));
            }
            if st.datasources.iter().any(|x| x.tenant_id == ds.tenant_id && x.name == ds.name && x.is_live()) {
                return Err(StoreError::Conflict(format!("datasource '{}' already exists for this tenant", ds.name)));
            }
            st.datasources.push(ds.clone());
        }
        Mutation::SetDatasourceStatus { id, status } => {
            let ds = st
                .datasources
                .iter_mut()
                .find(|d| &d.id == id && d.is_live())
                .ok_or_else(|| StoreError::NotFound("datasource".into()))?;
            ds.status.clone_from(status);
        }
        Mutation::DeleteDatasource { tenant_id, id, at } => {
            need_tenant(st, tenant_id)?;
            let ds = st
                .datasources
                .iter_mut()
                .find(|d| &d.tenant_id == tenant_id && &d.id == id && d.is_live())
                .ok_or_else(|| StoreError::NotFound("datasource".into()))?;
            ds.deleted_at = Some(*at);
            // The connection may carry credentials; a deleted datasource keeps only its metadata.
            ds.connection = json!({});
        }
        Mutation::CreateNode(n) => {
            need_tenant(st, &n.tenant_id)?;
            let version = st
                .nodes
                .iter()
                .filter(|x| x.tenant_id == n.tenant_id && x.name == n.name)
                .map(|x| x.version)
                .max()
                .unwrap_or(0)
                + 1;
            st.nodes.push(super::NodeRecord { version, ..n.clone() });
        }
        Mutation::DeleteNode { tenant_id, id, at } => {
            need_tenant(st, tenant_id)?;
            let n = st
                .nodes
                .iter_mut()
                .find(|n| &n.tenant_id == tenant_id && &n.id == id && n.is_live())
                .ok_or_else(|| StoreError::NotFound("node".into()))?;
            n.deleted_at = Some(*at);
        }
        Mutation::ProposeOntology { tenant_id, elements } => {
            need_tenant(st, tenant_id)?;
            let onto = st.ontologies.entry(tenant_id.clone()).or_insert_with(|| Ontology {
                tenant_id: tenant_id.clone(),
                version: 0,
                elements: vec![],
            });
            for e in elements {
                match onto.elements.iter_mut().find(|x| x.id == e.id) {
                    Some(x) => *x = e.clone(),
                    None => onto.elements.push(e.clone()),
                }
            }
            onto.version += 1;
        }
        Mutation::ReviewOntologyElement { id, status } => {
            let active: Vec<String> = st.tenants.iter().filter(|t| t.is_active()).map(|t| t.id.clone()).collect();
            let onto = st
                .ontologies
                .values_mut()
                .find(|o| active.contains(&o.tenant_id) && o.elements.iter().any(|e| &e.id == id))
                .ok_or_else(|| StoreError::NotFound("ontology element".into()))?;
            if let Some(e) = onto.elements.iter_mut().find(|e| &e.id == id) {
                e.status = *status;
            }
            // Any reviewed change publishes a new ontology version (cache keys include it).
            onto.version += 1;
        }
        Mutation::CreateDek { tenant_id, dek } => {
            need_tenant(st, tenant_id)?;
            if st.deks.contains_key(tenant_id) {
                return Err(StoreError::Conflict(format!("tenant '{tenant_id}' already has a data key")));
            }
            st.deks.insert(tenant_id.clone(), dek.clone());
        }
        Mutation::Rekey(r) => rekey(st, r)?,
    }
    Ok(())
}

/// Applies a [`super::Rekey`] batch: every change must still find the value it was planned from.
fn rekey(st: &mut State, r: &super::Rekey) -> Result<(), StoreError> {
    let stale = || StoreError::Conflict("keys changed while they were being re-keyed; run it again".into());
    for d in &r.deks {
        if !st.has_tenant(&d.tenant_id) || st.deks.get(&d.tenant_id).map(|x| &x.wrapped) != d.prev.as_ref() {
            return Err(stale());
        }
        st.deks.insert(d.tenant_id.clone(), d.next.clone());
    }
    for c in &r.provider_secrets {
        let p = st
            .provider_keys
            .iter_mut()
            .find(|p| p.tenant_id == c.tenant_id && p.id == c.id && p.secret.as_ref() == Some(&c.prev))
            .ok_or_else(stale)?;
        p.secret = Some(c.next.clone());
    }
    for c in &r.shared_secrets {
        let p = st
            .shared_providers
            .iter_mut()
            .find(|p| p.provider.id.as_str() == c.id && p.provider.api_key.as_ref() == Some(&c.prev))
            .ok_or_else(stale)?;
        p.provider.api_key = Some(c.next.clone());
    }
    for c in &r.datasources {
        let ds = st
            .datasources
            .iter_mut()
            .find(|d| d.tenant_id == c.tenant_id && d.id == c.id && d.is_live() && d.connection == c.prev)
            .ok_or_else(stale)?;
        ds.connection = c.next.clone();
    }
    Ok(())
}
