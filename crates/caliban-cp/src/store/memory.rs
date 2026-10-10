//! In-memory backend (dev/demo): state and audit chain live in the process.

use super::audit::{AuditEntry, now_micros};
use super::{
    Backend, Check, Mutation, NodeRecord, NodeState, PendingLogin, Promotion, RouterStatus, SessionRecord, State,
    StoreError, SubjectKind,
};
use caliban_nodes::publish::NodeCaps;
use caliban_ontology::Ontology;
use caliban_ontology::Status;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde_json::json;
use std::collections::BTreeMap;

pub struct MemoryBackend {
    inner: Mutex<(State, Vec<AuditEntry>)>,
    /// Ids of recorded data-plane audit events (see `Backend::record_once`). Locked after `inner`.
    recorded: Mutex<std::collections::HashSet<String>>,
    /// Sessions (by id) and pending logins (by state). Locked after `inner`, never before.
    auth: Mutex<AuthTables>,
    /// Router check-ins by router id (not part of the audited state).
    routers: Mutex<BTreeMap<String, RouterStatus>>,
}

#[derive(Default)]
struct AuthTables {
    sessions: BTreeMap<String, SessionRecord>,
    logins: BTreeMap<String, PendingLogin>,
}

impl MemoryBackend {
    /// Starts from `seed` and records the seeding as audit row 1 (as the Postgres backend does).
    pub fn seeded(mut seed: State) -> Self {
        let entry = AuditEntry::next(None, "system", &seed_draft(&seed), now_micros());
        seed.audit_head = entry.seq;
        Self {
            inner: Mutex::new((seed, vec![entry])),
            recorded: Mutex::default(),
            auth: Mutex::default(),
            routers: Mutex::default(),
        }
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
        apply_sessions(&mut self.auth.lock(), m, &st)?;
        let entry = AuditEntry::next(log.last(), actor, &draft, now_micros());
        st.audit_head = entry.seq;
        log.push(entry);
        *committed = st.clone();
        Ok(st)
    }

    async fn record_once(&self, actor: &str, event_id: &str, d: &super::audit::AuditDraft) -> Result<bool, StoreError> {
        let mut guard = self.inner.lock();
        if !self.recorded.lock().insert(event_id.to_owned()) {
            return Ok(false);
        }
        let (committed, log) = &mut *guard;
        let entry = AuditEntry::next(log.last(), actor, d, now_micros());
        committed.audit_head = entry.seq;
        log.push(entry);
        Ok(true)
    }

    async fn audit(&self, limit: usize) -> Result<Vec<AuditEntry>, StoreError> {
        let g = self.inner.lock();
        Ok(g.1[g.1.len().saturating_sub(limit)..].to_vec())
    }

    async fn session(&self, token_sha256: &str) -> Result<Option<SessionRecord>, StoreError> {
        Ok(self.auth.lock().sessions.values().find(|s| s.token_sha256 == token_sha256).cloned())
    }

    async fn touch_session(&self, id: &str, at: DateTime<Utc>) -> Result<(), StoreError> {
        if let Some(s) = self.auth.lock().sessions.get_mut(id) {
            s.last_seen_at = at;
        }
        Ok(())
    }

    async fn active_sessions(&self, user_id: &str, now: DateTime<Utc>) -> Result<Vec<SessionRecord>, StoreError> {
        let mut v: Vec<SessionRecord> = self
            .auth
            .lock()
            .sessions
            .values()
            .filter(|s| s.user_id == user_id && s.revoked_at.is_none() && s.expires_at > now)
            .cloned()
            .collect();
        v.sort_by_key(|s| s.created_at);
        Ok(v)
    }

    async fn put_login(&self, login: &PendingLogin) -> Result<(), StoreError> {
        let mut a = self.auth.lock();
        if a.logins.contains_key(&login.state) {
            return Err(StoreError::Conflict("login state already exists".into()));
        }
        a.logins.insert(login.state.clone(), login.clone());
        Ok(())
    }

    async fn take_login(&self, state: &str) -> Result<Option<PendingLogin>, StoreError> {
        Ok(self.auth.lock().logins.remove(state))
    }

    async fn purge_auth(&self, now: DateTime<Utc>) -> Result<u64, StoreError> {
        let mut a = self.auth.lock();
        let before = a.sessions.len() + a.logins.len();
        a.sessions.retain(|_, s| s.expires_at >= now);
        a.logins.retain(|_, l| l.expires_at >= now);
        Ok((before - a.sessions.len() - a.logins.len()) as u64)
    }

    async fn put_router(&self, r: &RouterStatus) -> Result<(), StoreError> {
        let mut routers = self.routers.lock();
        if routers.get(&r.router_id).is_none_or(|old| old.last_seen <= r.last_seen) {
            routers.insert(r.router_id.clone(), r.clone());
        }
        Ok(())
    }

    async fn routers(&self) -> Result<Vec<RouterStatus>, StoreError> {
        let mut v: Vec<RouterStatus> = self.routers.lock().values().cloned().collect();
        v.sort_by(|a, b| b.last_seen.cmp(&a.last_seen).then_with(|| a.router_id.cmp(&b.router_id)));
        Ok(v)
    }
}

/// The session side of `Login`, `Logout` and `RevokeUserSessions` (sessions are not in
/// [`State`]). `st` is the state after [`apply_to`]. `postgres.rs` matches it.
fn apply_sessions(a: &mut AuthTables, m: &Mutation, st: &State) -> Result<(), StoreError> {
    match m {
        Mutation::Login { user, session } => {
            let owner = st
                .user_by_subject(&user.issuer, &user.subject)
                .ok_or_else(|| StoreError::Backend("login user not applied".into()))?;
            if a.sessions.contains_key(&session.id)
                || a.sessions.values().any(|s| s.token_sha256 == session.token_sha256)
            {
                return Err(StoreError::Conflict("session already exists".into()));
            }
            a.sessions.insert(session.id.clone(), SessionRecord { user_id: owner.id.clone(), ..session.clone() });
        }
        Mutation::Logout { session_id, user_id, at } => {
            let s = a
                .sessions
                .get_mut(session_id)
                .filter(|s| &s.user_id == user_id && s.revoked_at.is_none())
                .ok_or_else(|| StoreError::NotFound("session".into()))?;
            s.revoked_at = Some(*at);
        }
        Mutation::RevokeUserSessions { user_id, at } => {
            for s in a.sessions.values_mut().filter(|s| &s.user_id == user_id && s.revoked_at.is_none()) {
                s.revoked_at = Some(*at);
            }
        }
        _ => {}
    }
    Ok(())
}

fn need_tenant(st: &State, id: &str) -> Result<(), StoreError> {
    if st.has_tenant(id) { Ok(()) } else { Err(StoreError::NotFound("tenant".into())) }
}

/// The in-memory meaning of each mutation. `postgres.rs` must match it (enforced by the parity
/// test suite).
pub(super) fn apply_to(st: &mut State, m: &Mutation) -> Result<(), StoreError> {
    match m {
        Mutation::CreateTenant(t) => {
            check_fraction(t.auto_cache_hit_fraction)?;
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
            st.promotions.remove(id);
            st.role_bindings.retain(|b| b.tenant_id.as_ref() != Some(id));
            for s in st.tool_servers.iter_mut().filter(|s| &s.tenant_id == id && s.is_live()) {
                s.deleted_at = Some(*at);
                s.secret = None;
                s.has_credential = false;
            }
        }
        Mutation::UpdateTenant {
            id,
            pii_default,
            pii_surrogate_scope,
            semantic_cache,
            auto_cache_hit_fraction,
            node_caps,
            node_spend_caps,
        } => {
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
            if let Some(f) = auto_cache_hit_fraction {
                check_fraction(*f)?;
                t.auto_cache_hit_fraction = *f;
            }
            if let Some(c) = node_caps {
                if let Some(c) = c {
                    c.validate().map_err(StoreError::Invalid)?;
                }
                t.node_caps = *c;
            }
            if let Some(c) = node_spend_caps {
                if let Some(c) = c {
                    c.validate().map_err(StoreError::Invalid)?;
                }
                t.node_spend_caps = *c;
            }
        }
        Mutation::CreateApiKey(k) => {
            need_tenant(st, &k.tenant_id)?;
            if let Some(bad) = k.nodes.iter().flatten().find(|n| !caliban_nodes::valid_node_name(n)) {
                return Err(StoreError::Invalid(format!("'{bad}' is not a node name")));
            }
            if st.api_keys.iter().any(|x| x.hash == k.hash || x.id == k.id) {
                return Err(StoreError::Conflict("api key already exists".into()));
            }
            st.api_keys.push(k.clone());
        }
        Mutation::UpdateApiKey { tenant_id, id, nodes, datasource_scopes } => {
            need_tenant(st, tenant_id)?;
            if let Some(bad) = nodes.iter().flatten().flatten().find(|n| !caliban_nodes::valid_node_name(n)) {
                return Err(StoreError::Invalid(format!("'{bad}' is not a node name")));
            }
            let k = st
                .api_keys
                .iter_mut()
                .find(|k| &k.tenant_id == tenant_id && &k.id == id && k.is_active())
                .ok_or_else(|| StoreError::NotFound("api key".into()))?;
            if let Some(n) = nodes {
                k.nodes.clone_from(n);
            }
            if let Some(s) = datasource_scopes {
                k.datasource_scopes.clone_from(s);
            }
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
            if !caliban_nodes::valid_node_name(&n.name) {
                return Err(StoreError::Invalid(format!(
                    "'{}' is not a node name (1 to 64 characters of a-z, 0-9, '-' and '_')",
                    n.name
                )));
            }
            let version = st
                .nodes
                .iter()
                .filter(|x| x.tenant_id == n.tenant_id && x.name == n.name)
                .map(|x| x.version)
                .max()
                .unwrap_or(0)
                + 1;
            st.nodes.push(super::NodeRecord {
                version,
                state: NodeState::Draft,
                published_at: None,
                retired_at: None,
                sealed_spec: None,
                ..n.clone()
            });
        }
        Mutation::DeleteNode { tenant_id, id, at } => {
            need_tenant(st, tenant_id)?;
            let n = st
                .nodes
                .iter_mut()
                .find(|n| &n.tenant_id == tenant_id && &n.id == id && n.is_live())
                .ok_or_else(|| StoreError::NotFound("node".into()))?;
            if n.state == NodeState::Published {
                return Err(StoreError::Conflict(format!(
                    "{}@v{} is published: retire it before deleting it",
                    n.name, n.version
                )));
            }
            n.deleted_at = Some(*at);
        }
        Mutation::PublishNode { tenant_id, name, version, sealed_spec, promote, at, by } => {
            need_tenant(st, tenant_id)?;
            let n = st
                .node_version(tenant_id, name, *version)
                .ok_or_else(|| StoreError::NotFound("node version".into()))?;
            match n.state {
                NodeState::Draft => {}
                NodeState::Published => {
                    return Err(StoreError::Conflict(format!("{name}@v{version} is already published")));
                }
                NodeState::Retired => {
                    return Err(StoreError::Conflict(format!("{name}@v{version} is retired; create a new version")));
                }
            }
            let spec = parse_spec(n)?;
            caliban_nodes::publish::validate_for_publish(name, *version, &spec, &TenantNodes { st, tenant: tenant_id })
                .map_err(|e| StoreError::Invalid(e.to_string()))?;
            if !st.deks.contains_key(tenant_id) {
                return Err(StoreError::Invalid(format!(
                    "{name}@v{version} is sealed under a tenant key that does not exist"
                )));
            }
            let n = st
                .nodes
                .iter_mut()
                .find(|n| &n.tenant_id == tenant_id && &n.name == name && n.version == *version && n.is_live())
                .ok_or_else(|| StoreError::NotFound("node version".into()))?;
            n.state = NodeState::Published;
            n.published_at = Some(*at);
            n.sealed_spec = Some(sealed_spec.clone());
            if *promote {
                promote_to(st, tenant_id, name, *version, *at, by);
            }
        }
        Mutation::PromoteNode { tenant_id, name, version, at, by } => {
            need_tenant(st, tenant_id)?;
            let n = st
                .node_version(tenant_id, name, *version)
                .ok_or_else(|| StoreError::NotFound("node version".into()))?;
            if n.state != NodeState::Published {
                return Err(StoreError::Conflict(format!(
                    "{name}@v{version} is {}: only published versions can be promoted",
                    n.state.as_str()
                )));
            }
            let over = st.node_caps(tenant_id).violations(&parse_spec(n)?);
            if !over.is_empty() {
                return Err(StoreError::Invalid(format!("cannot promote {name}@v{version}: {}", over.join("; "))));
            }
            promote_to(st, tenant_id, name, *version, *at, by);
        }
        Mutation::RetireNode { tenant_id, name, version, at } => {
            need_tenant(st, tenant_id)?;
            let n = st
                .node_version(tenant_id, name, *version)
                .ok_or_else(|| StoreError::NotFound("node version".into()))?;
            if n.state != NodeState::Published {
                return Err(StoreError::Conflict(format!(
                    "{name}@v{version} is {}: only published versions can be retired",
                    n.state.as_str()
                )));
            }
            // A published version that calls this one would break.
            let callers: Vec<String> = st
                .nodes
                .iter()
                .filter(|x| &x.tenant_id == tenant_id && x.is_live() && x.state == NodeState::Published)
                .filter(|x| !(&x.name == name && x.version == *version))
                .filter(|x| {
                    parse_spec(x).is_ok_and(|s| s.node_refs().iter().any(|(rn, rv)| rn == name && rv == version))
                })
                .map(|x| format!("{}@v{}", x.name, x.version))
                .collect();
            if !callers.is_empty() {
                return Err(StoreError::Conflict(format!(
                    "{name}@v{version} is called by {}; retire those first",
                    callers.join(", ")
                )));
            }
            let n = st
                .nodes
                .iter_mut()
                .find(|n| &n.tenant_id == tenant_id && &n.name == name && n.version == *version && n.is_live())
                .ok_or_else(|| StoreError::NotFound("node version".into()))?;
            n.state = NodeState::Retired;
            n.retired_at = Some(*at);
            if st.promotion(tenant_id, name).is_some_and(|p| p.version == *version)
                && let Some(p) = st.promotions.get_mut(tenant_id)
            {
                p.remove(name);
                if p.is_empty() {
                    st.promotions.remove(tenant_id);
                }
            }
        }
        Mutation::CreateToolServer(s) => {
            need_tenant(st, &s.tenant_id)?;
            if !caliban_nodes::valid_node_name(&s.name) {
                return Err(StoreError::Invalid(format!(
                    "'{}' is not a tool server name (1 to 64 characters of a-z, 0-9, '-' and '_')",
                    s.name
                )));
            }
            if st.tool_server(&s.tenant_id, &s.name).is_some() {
                return Err(StoreError::Conflict(format!("tool server '{}' already exists", s.name)));
            }
            if s.secret.is_some() && !st.deks.contains_key(&s.tenant_id) {
                return Err(StoreError::Invalid(
                    "the credential is sealed under a tenant key that does not exist".into(),
                ));
            }
            st.tool_servers.push(super::ToolServerRecord { has_credential: s.secret.is_some(), ..s.clone() });
        }
        Mutation::DeleteToolServer { tenant_id, name, at } => {
            need_tenant(st, tenant_id)?;
            st.tool_server(tenant_id, name).ok_or_else(|| StoreError::NotFound("tool server".into()))?;
            // A published version that calls one of its tools would break: retire it first.
            let users: Vec<String> = st
                .nodes
                .iter()
                .filter(|n| &n.tenant_id == tenant_id && n.is_live() && n.state == NodeState::Published)
                .filter(|n| {
                    parse_spec(n).is_ok_and(|s| {
                        s.tools.iter().any(|t| {
                            matches!(caliban_nodes::ToolTarget::parse(&t.reference), Ok(caliban_nodes::ToolTarget::Mcp { server, .. }) if &server == name)
                        })
                    })
                })
                .map(|n| format!("{}@v{}", n.name, n.version))
                .collect();
            if !users.is_empty() {
                return Err(StoreError::Conflict(format!(
                    "tool server '{name}' is used by {}; retire those first",
                    users.join(", ")
                )));
            }
            let s = st
                .tool_servers
                .iter_mut()
                .find(|s| &s.tenant_id == tenant_id && &s.name == name && s.is_live())
                .ok_or_else(|| StoreError::NotFound("tool server".into()))?;
            s.deleted_at = Some(*at);
            s.secret = None;
            s.has_credential = false;
        }
        Mutation::RecordToolManifests { tenant_id, server, manifests } => {
            need_tenant(st, tenant_id)?;
            st.tool_server(tenant_id, server).ok_or_else(|| StoreError::NotFound("tool server".into()))?;
            for m in manifests {
                let known = st
                    .tool_manifests
                    .iter()
                    .any(|x| &x.tenant_id == tenant_id && &x.server == server && x.name == m.name && x.pin == m.pin);
                if !known {
                    st.tool_manifests.push(super::ToolManifestRecord {
                        tenant_id: tenant_id.clone(),
                        server: server.clone(),
                        status: super::ToolStatus::Discovered,
                        approved_at: None,
                        approved_by: None,
                        findings_acknowledged: false,
                        ..m.clone()
                    });
                }
            }
        }
        Mutation::ApproveTool { tenant_id, server, tool, pin, acknowledge_findings, at, by } => {
            need_tenant(st, tenant_id)?;
            st.tool_server(tenant_id, server).ok_or_else(|| StoreError::NotFound("tool server".into()))?;
            let m = st
                .tool_manifests
                .iter_mut()
                .find(|m| &m.tenant_id == tenant_id && &m.server == server && &m.name == tool && &m.pin == pin)
                .ok_or_else(|| StoreError::NotFound("tool manifest".into()))?;
            if !m.findings.is_empty() && !acknowledge_findings {
                return Err(StoreError::Invalid(format!(
                    "the injection scan flagged this manifest ({}); approve it with acknowledge_findings: true if a human reviewed them",
                    m.findings.iter().map(|f| format!("{} in {}", f.kind, f.location)).collect::<Vec<_>>().join(", ")
                )));
            }
            m.status = super::ToolStatus::Approved;
            m.approved_at = Some(*at);
            m.approved_by = Some(by.clone());
            m.findings_acknowledged = !m.findings.is_empty() && *acknowledge_findings;
        }
        Mutation::RevokeTool { tenant_id, server, tool, pin } => {
            need_tenant(st, tenant_id)?;
            let m = st
                .tool_manifests
                .iter_mut()
                .find(|m| &m.tenant_id == tenant_id && &m.server == server && &m.name == tool && &m.pin == pin)
                .ok_or_else(|| StoreError::NotFound("tool manifest".into()))?;
            m.status = super::ToolStatus::Revoked;
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
        Mutation::Login { user, .. } => {
            match st.users.iter_mut().find(|u| u.issuer == user.issuer && u.subject == user.subject) {
                Some(u) => {
                    u.email.clone_from(&user.email);
                    u.name.clone_from(&user.name);
                    u.last_login_at = user.last_login_at;
                }
                None => {
                    if st.users.iter().any(|u| u.id == user.id) {
                        return Err(StoreError::Conflict("user id already exists".into()));
                    }
                    st.users.push(user.clone());
                }
            }
        }
        Mutation::Logout { user_id, .. } | Mutation::RevokeUserSessions { user_id, .. } => {
            if st.user(user_id).is_none() {
                return Err(StoreError::NotFound("user".into()));
            }
        }
        Mutation::CreateUser(user) => {
            if st.user_by_subject(&user.issuer, &user.subject).is_some() || st.user(&user.id).is_some() {
                return Err(StoreError::Conflict("user already exists".into()));
            }
            st.users.push(user.clone());
        }
        Mutation::CreateRoleBinding(b) => {
            if b.role.is_tenant_role() != b.tenant_id.is_some() {
                return Err(StoreError::Invalid(if b.role.is_tenant_role() {
                    format!("role '{}' is a tenant role: tenant_id is required", b.role.as_str())
                } else {
                    format!("role '{}' is deployment-wide: tenant_id must be empty", b.role.as_str())
                }));
            }
            if let Some(t) = &b.tenant_id {
                need_tenant(st, t)?;
            }
            if b.subject.trim().is_empty() {
                return Err(StoreError::Invalid("subject must not be empty".into()));
            }
            if b.subject_kind == SubjectKind::User && st.user(&b.subject).is_none() {
                return Err(StoreError::NotFound("user".into()));
            }
            if st.role_bindings.iter().any(|x| {
                x.id == b.id
                    || (x.subject_kind == b.subject_kind
                        && x.subject == b.subject
                        && x.role == b.role
                        && x.tenant_id == b.tenant_id)
            }) {
                return Err(StoreError::Conflict("this role binding already exists".into()));
            }
            st.role_bindings.push(b.clone());
        }
        Mutation::DeleteRoleBinding { id } => {
            let pos = st
                .role_bindings
                .iter()
                .position(|b| &b.id == id)
                .ok_or_else(|| StoreError::NotFound("role binding".into()))?;
            st.role_bindings.remove(pos);
        }
        Mutation::Record(_) => {}
    }
    Ok(())
}

fn parse_spec(n: &NodeRecord) -> Result<caliban_nodes::NodeSpec, StoreError> {
    serde_json::from_value(n.spec.clone())
        .map_err(|e| StoreError::Invalid(format!("{}@v{}: invalid node spec: {e}", n.name, n.version)))
}

fn promote_to(st: &mut State, tenant: &str, name: &str, version: u32, at: DateTime<Utc>, by: &str) {
    st.promotions
        .entry(tenant.to_owned())
        .or_default()
        .insert(name.to_owned(), Promotion { version, promoted_at: at, promoted_by: by.to_owned() });
}

/// Publish-time validation against the committed state of one tenant.
pub(crate) struct TenantNodes<'a> {
    pub st: &'a State,
    pub tenant: &'a str,
}

impl caliban_nodes::publish::PublishContext for TenantNodes<'_> {
    /// `<datasource>.<object>:<access>`: `<datasource>` is a live datasource of the tenant (by
    /// name); `<object>` is `*` or a collection (or entity name) of an approved ontology entity
    /// bound to that datasource.
    fn scope_exists(&self, scope: &str) -> Result<(), String> {
        let (target, access) = scope.rsplit_once(':').ok_or("expected <datasource>.<object>:<access>")?;
        if !matches!(access, "read" | "write") {
            return Err(format!("access must be read or write, not '{access}'"));
        }
        let (ds, object) = target.split_once('.').ok_or("expected <datasource>.<object>:<access>")?;
        let d = self
            .st
            .datasources
            .iter()
            .find(|d| d.tenant_id == self.tenant && d.is_live() && d.name.eq_ignore_ascii_case(ds))
            .ok_or_else(|| format!("the tenant has no datasource named '{ds}'"))?;
        if object == "*" {
            return Ok(());
        }
        let bound = self.st.ontologies.get(self.tenant).into_iter().flat_map(|o| o.elements.iter()).any(|e| {
            e.status == Status::Approved
                && match &e.spec {
                    caliban_ontology::ElementSpec::Entity(def) => match &def.binding {
                        caliban_ontology::model::EntityBinding::Root { datasource, collection, .. } => {
                            (datasource == &d.id || datasource.eq_ignore_ascii_case(&d.name))
                                && (collection == object || e.name == object || e.id == object)
                        }
                        caliban_ontology::model::EntityBinding::Embedded { .. } => false,
                    },
                    _ => false,
                }
        });
        if bound {
            Ok(())
        } else {
            Err(format!("no approved ontology entity of datasource '{ds}' is named '{object}'"))
        }
    }

    fn version(&self, name: &str, version: u32) -> caliban_nodes::publish::RefState {
        use caliban_nodes::publish::RefState;
        match self.st.node_version(self.tenant, name, version) {
            None => RefState::Missing,
            Some(n) => match n.state {
                NodeState::Draft => RefState::Draft,
                NodeState::Retired => RefState::Retired,
                NodeState::Published => match serde_json::from_value(n.spec.clone()) {
                    Ok(spec) => RefState::Published(Box::new(spec)),
                    Err(_) => RefState::Missing,
                },
            },
        }
    }

    fn caps(&self) -> NodeCaps {
        self.st.node_caps(self.tenant)
    }

    /// `mcp://server/tool#pin` must name an approved manifest, with exactly that pin, of a live
    /// server the tenant registered.
    fn check_tool(&self, target: &caliban_nodes::ToolTarget) -> Result<(), String> {
        let caliban_nodes::ToolTarget::Mcp { server, tool, pin } = target else { return Ok(()) };
        if self.st.tool_server(self.tenant, server).is_none() {
            return Err(format!("the tenant has no tool server named '{server}'"));
        }
        if self.st.approved_tool(self.tenant, server, tool, pin).is_some() {
            return Ok(());
        }
        let other = self.st.tool_manifests.iter().find(|m| {
            m.tenant_id == self.tenant
                && &m.server == server
                && &m.name == tool
                && m.status == super::ToolStatus::Approved
        });
        Err(match other {
            Some(m) => format!("the approved manifest of '{tool}' has pin {}, not {pin}", m.pin),
            None => format!("'{tool}' has no approved manifest on server '{server}'"),
        })
    }
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

/// Range check before any backend write (the Postgres CHECK constraint would otherwise surface as
/// a backend error rather than an invalid request).
fn check_fraction(f: Option<f64>) -> Result<(), StoreError> {
    match f {
        Some(f) if !f.is_finite() || !(0.0..=1.0).contains(&f) => {
            Err(StoreError::Invalid(format!("auto_cache_hit_fraction must be in 0..=1, got {f}")))
        }
        _ => Ok(()),
    }
}
