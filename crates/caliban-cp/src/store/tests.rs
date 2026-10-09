//! Store parity: one behaviour suite, run against the memory backend and (when
//! `CALIBAN_TEST_DATABASE_URL` is set) the Postgres backend; the final states must match.

use super::audit::verify_chain;
use super::postgres::{MIGRATIONS, PgBackend};
use super::*;
use caliban_config::seal;
use chrono::TimeZone;
use sqlx::AssertSqlSafe;
use sqlx::postgres::PgConnectOptions;

const KEY_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

const BASE: &str = r#"
[[providers]]
id = "pool"
kind = "openai_compatible"
base_url = "http://pool:8000/v1"
trust_tier = "t0_sovereign"
cache_salt = true

[[models]]
id = "local/qwen"
provider = "pool"
upstream_model = "Qwen/Qwen3-8B"
family = "qwen3"
trust_tier = "t0_sovereign"
context_window = 32768
price_in_per_mtok = 0.0
[models.capabilities]
tools = true
reasoning = "hybrid"
reasoning_control = "enable_thinking"

[[models]]
id = "ext/gpt"
provider = "openai"
upstream_model = "gpt-5-mini"
trust_tier = "t2_contracted"
price_in_per_mtok = 0.25
price_out_per_mtok = 2.0
price_cache_read_per_mtok = 0.1
price_cache_write_per_mtok = 0.3
price_cache_write_1h_per_mtok = 0.5

[[tenants]]
id = "acme"
name = "Acme"
pii_mode = "mask"
api_key_hashes = ["1111111111111111111111111111111111111111111111111111111111111111"]
  [[tenants.providers]]
  id = "openai"
  kind = "openai"
  base_url = "https://api.openai.com/v1"
  trust_tier = "t2_contracted"
  api_key = { env = "ACME_OPENAI_API_KEY" }
  [[tenants.routes]]
  intent = "default"
  models = ["local/qwen", "ext/gpt"]
  [[tenants.routes]]
  intent = "code"
  models = ["ext/gpt"]
"#;

fn base() -> Config {
    Config::from_toml_str(BASE).unwrap()
}

fn handle(cfg: &Config) -> ConfigHandle {
    ConfigHandle::new(Snapshot::new(cfg.clone(), "boot"))
}

fn ts() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 1, 12, 0, 0).unwrap()
}

/// When deletes in the suite happen (fixed, so both backends store the same value).
fn del_ts() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 2, 9, 30, 0).unwrap()
}

fn tenant(id: &str) -> Tenant {
    Tenant {
        id: id.into(),
        name: id.to_uppercase(),
        region: Some("eu".into()),
        pii_default: PiiMode::Off,
        pii_surrogate_scope: PiiSurrogateScope::Tenant,
        semantic_cache: SemanticCacheMode::Off,
        created_at: ts(),
        status: TenantStatus::Active,
        deleted_at: None,
        settings: Map::new(),
    }
}

fn model(v: Value) -> ModelEntry {
    serde_json::from_value(v).unwrap()
}

fn element(id: &str) -> Element {
    serde_json::from_value(json!({
        "id": id, "name": id, "description": null, "synonyms": ["rev"], "status": "proposed",
        "provenance": "llm", "confidence": 0.5, "kind": "glossary_term",
        "spec": {"phrase": format!("{id} phrase"), "maps_to": "orders.total"}
    }))
    .unwrap()
}

fn node(id: &str, tenant: &str, name: &str) -> NodeRecord {
    NodeRecord { id: id.into(), tenant_id: tenant.into(), name: name.into(), version: 0, spec: json!({"k": 1}), created_at: ts(), deleted_at: None }
}

async fn pg_backend() -> Option<PgBackend> {
    let url = std::env::var("CALIBAN_TEST_DATABASE_URL").ok()?;
    // Each test gets its own schema so tests run in parallel against one database.
    let schema = format!("t_{}", uuid::Uuid::now_v7().simple());
    let admin = sqlx::PgPool::connect(&url).await.expect("CALIBAN_TEST_DATABASE_URL must be reachable");
    sqlx::raw_sql(AssertSqlSafe(format!("CREATE SCHEMA {schema}"))).execute(&admin).await.unwrap();
    let opts: PgConnectOptions = url.parse::<PgConnectOptions>().unwrap().options([("search_path", schema.as_str())]);
    Some(PgBackend::connect_with(opts).await.unwrap())
}

const A: &str = "admin";

/// One sealed blob for every run (sealing uses a random nonce).
fn sealed_blob() -> String {
    static S: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    S.get_or_init(|| seal(&[7u8; 32], "sk-test-1234")).clone()
}

/// The behaviour every backend must have. Returns the number of audit rows expected.
async fn suite(s: &Store) {
    // ── seed from the config file ──
    let st = s.state();
    assert_eq!(st.tenants.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(), ["acme"]);
    assert_eq!(st.tenants[0].pii_default, PiiMode::Mask);
    assert_eq!(st.tenants[0].pii_surrogate_scope, PiiSurrogateScope::Tenant, "tenant scope by default");
    assert_eq!(st.routes["acme"].iter().map(|r| r.intent.as_str()).collect::<Vec<_>>(), ["default", "code"]);
    assert_eq!(st.routes["acme"][0].models.iter().map(|m| m.as_str()).collect::<Vec<_>>(), ["local/qwen", "ext/gpt"]);
    assert_eq!(st.provider_keys[0].secret, Some(SecretRef::Env { env: "ACME_OPENAI_API_KEY".into() }));
    assert!(st.shared_providers[0].provider.cache_salt);
    assert_eq!(st.models[0].capabilities.reasoning, caliban_config::Reasoning::Hybrid);
    assert_eq!(st.models[0].context_window, Some(32768));
    assert_eq!(st.audit_head, 1);
    let snap = s.config.load();
    assert_eq!(snap.version, "cp-1");
    assert_eq!(snap.tenant_by_key_hash(KEY_HASH).unwrap().id.as_str(), "acme");

    // ── tenants & keys ──
    s.apply(A, Mutation::CreateTenant(tenant("globex"))).await.unwrap();
    assert_eq!(
        s.apply(A, Mutation::CreateTenant(tenant("globex"))).await.unwrap_err(),
        StoreError::Conflict("tenant 'globex' already exists".into())
    );
    // PII settings: session scope is a per-tenant opt-in, shipped in the snapshot.
    let to_session = Mutation::UpdateTenant { id: "globex".into(), pii_default: None, pii_surrogate_scope: Some(PiiSurrogateScope::Session), semantic_cache: None };
    s.apply(A, to_session).await.unwrap();
    let g = s.state().tenant("globex").cloned().unwrap();
    assert_eq!((g.pii_default, g.pii_surrogate_scope), (PiiMode::Off, PiiSurrogateScope::Session));
    let snap = s.config.load();
    assert_eq!(snap.pii_surrogate_scope_for(snap.tenant(&"globex".into()).unwrap()), PiiSurrogateScope::Session);
    assert_eq!(snap.pii_surrogate_scope_for(snap.tenant(&"acme".into()).unwrap()), PiiSurrogateScope::Tenant);
    // Semantic cache: off by default, switched on per tenant, shipped in the snapshot.
    assert_eq!(s.state().tenant("globex").unwrap().semantic_cache, SemanticCacheMode::Off);
    let on = Mutation::UpdateTenant { id: "globex".into(), pii_default: None, pii_surrogate_scope: None, semantic_cache: Some(SemanticCacheMode::On) };
    s.apply(A, on).await.unwrap();
    let g = s.state().tenant("globex").cloned().unwrap();
    assert_eq!((g.semantic_cache, g.pii_surrogate_scope), (SemanticCacheMode::On, PiiSurrogateScope::Session), "other settings kept");
    let snap = s.config.load();
    assert_eq!(snap.tenant(&"globex".into()).unwrap().semantic_cache, SemanticCacheMode::On);
    assert_eq!(snap.tenant(&"acme".into()).unwrap().semantic_cache, SemanticCacheMode::Off);
    let ghost = Mutation::UpdateTenant { id: "nobody".into(), pii_default: Some(PiiMode::Mask), pii_surrogate_scope: None, semantic_cache: None };
    assert_eq!(s.apply(A, ghost).await.unwrap_err(), StoreError::NotFound("tenant".into()));
    let key = ApiKeyRecord {
        id: "key_g1".into(),
        tenant_id: "globex".into(),
        name: "ci".into(),
        prefix: "cal_2222".into(),
        hash: "2".repeat(64),
        created_at: ts(),
        revoked_at: None,
    };
    s.apply(A, Mutation::CreateApiKey(key.clone())).await.unwrap();
    assert_eq!(s.config.load().tenant_by_key_hash(&"2".repeat(64)).unwrap().id.as_str(), "globex");
    let orphan = ApiKeyRecord { id: "key_x".into(), tenant_id: "nobody".into(), hash: "3".repeat(64), ..key.clone() };
    assert_eq!(s.apply(A, Mutation::CreateApiKey(orphan)).await.unwrap_err(), StoreError::NotFound("tenant".into()));
    assert!(matches!(s.apply(A, Mutation::CreateApiKey(key)).await.unwrap_err(), StoreError::Conflict(_)));

    // ── BYOK: sealed blob round-trips unchanged ──
    let sealed = sealed_blob();
    let byok = ProviderKeyRecord {
        id: "openai".into(),
        tenant_id: "globex".into(),
        kind: ProviderKind::Openai,
        label: "OpenAI".into(),
        base_url: None,
        trust_tier: TrustTier::T2Contracted,
        last4: Some("1234".into()),
        cache_salt: false,
        created_at: ts(),
        secret: Some(SecretRef::Sealed { sealed: sealed.clone() }),
    };
    s.apply(A, Mutation::CreateProviderKey(byok.clone())).await.unwrap();
    assert_eq!(
        s.apply(A, Mutation::CreateProviderKey(byok)).await.unwrap_err(),
        StoreError::Conflict("provider 'openai' already exists for this tenant".into())
    );
    let snap = s.config.load();
    let globex = snap.tenant(&"globex".into()).unwrap();
    assert_eq!(globex.providers[0].api_key, Some(SecretRef::Sealed { sealed }));
    assert_eq!(globex.providers[0].base_url, "https://api.openai.com/v1");

    // ── routes: validated, and a rejected change writes nothing ──
    let routes = vec![RouteConfig { intent: "default".into(), models: vec!["ext/gpt".into()] }];
    s.apply(A, Mutation::SetRoutes { tenant_id: "globex".into(), routes: routes.clone() }).await.unwrap();
    let head = s.state().audit_head;
    let bad = vec![RouteConfig { intent: "default".into(), models: vec!["nope".into()] }];
    assert!(matches!(s.apply(A, Mutation::SetRoutes { tenant_id: "globex".into(), routes: bad }).await, Err(StoreError::Invalid(_))));
    assert_eq!(s.state().routes["globex"][0].models[0].as_str(), "ext/gpt");
    assert!(matches!(
        s.apply(A, Mutation::DeleteProviderKey { tenant_id: "globex".into(), id: "openai".into() }).await,
        Err(StoreError::Invalid(_))
    ));
    assert!(s.state().provider_keys.iter().any(|p| p.tenant_id == "globex"));
    assert!(matches!(s.apply(A, Mutation::DeleteModel("ext/gpt".into())).await, Err(StoreError::Invalid(_))));
    assert_eq!(s.state().audit_head, head, "rejected mutations are not audited");
    assert_eq!(s.backend.head().await.unwrap(), head);

    // ── models ──
    assert_eq!(
        s.apply(A, Mutation::CreateModel(model(json!({"id": "local/qwen", "provider": "pool", "upstream_model": "x", "trust_tier": "t0_sovereign"}))))
            .await
            .unwrap_err(),
        StoreError::Conflict("model 'local/qwen' already exists".into())
    );
    let emb = model(json!({"id": "local/embed", "provider": "pool", "upstream_model": "Qwen/Qwen3-Embedding-0.6B",
                           "kind": "embedding", "trust_tier": "t0_sovereign", "licence": "apache-2.0",
                           "capabilities": {"vision": true}}));
    s.apply(A, Mutation::CreateModel(emb)).await.unwrap();
    let m = s.state().models.iter().find(|m| m.id.as_str() == "local/embed").cloned().unwrap();
    assert_eq!((m.kind, m.capabilities.vision, m.licence.as_deref()), (caliban_config::ModelKind::Embedding, true, Some("apache-2.0")));
    s.apply(A, Mutation::DeleteModel("local/embed".into())).await.unwrap();
    assert_eq!(s.apply(A, Mutation::DeleteModel("local/embed".into())).await.unwrap_err(), StoreError::NotFound("model".into()));

    // ── shared providers ──
    let gpu: SharedProvider = serde_json::from_value(json!({
        "id": "gpu-b", "kind": "openai_compatible", "base_url": "http://b:8000/v1", "trust_tier": "t0_sovereign",
        "api_key": {"file": "/run/secrets/b"}, "tenants": ["globex"]
    }))
    .unwrap();
    s.apply(A, Mutation::CreateSharedProvider(gpu.clone())).await.unwrap();
    assert!(matches!(s.apply(A, Mutation::CreateSharedProvider(gpu)).await, Err(StoreError::Conflict(_))));
    let st = s.state();
    let b = st.shared_providers.iter().find(|p| p.provider.id.as_str() == "gpu-b").unwrap();
    assert_eq!(b.tenants.iter().map(ToString::to_string).collect::<Vec<_>>(), ["globex"]);
    assert_eq!(b.provider.api_key, Some(SecretRef::File { file: "/run/secrets/b".into() }));
    assert!(matches!(s.apply(A, Mutation::DeleteSharedProvider("pool".into())).await, Err(StoreError::Invalid(_))));
    s.apply(A, Mutation::DeleteSharedProvider("gpu-b".into())).await.unwrap();

    // ── datasources ──
    let ds = DatasourceRecord {
        id: "ds_1".into(),
        tenant_id: "globex".into(),
        kind: "mongodb".into(),
        name: "sales".into(),
        status: "pending".into(),
        epoch: 0,
        connection: json!({"uri": {"env": "SALES_URI"}}),
        deleted_at: None,
    };
    s.apply(A, Mutation::CreateDatasource(ds.clone())).await.unwrap();
    assert!(matches!(s.apply(A, Mutation::CreateDatasource(DatasourceRecord { id: "ds_2".into(), ..ds })).await, Err(StoreError::Conflict(_))));
    s.apply(A, Mutation::SetDatasourceStatus { id: "ds_1".into(), status: "introspecting".into() }).await.unwrap();
    assert_eq!(s.state().datasources[0].status, "introspecting");
    assert_eq!(
        s.apply(A, Mutation::SetDatasourceStatus { id: "nope".into(), status: "x".into() }).await.unwrap_err(),
        StoreError::NotFound("datasource".into())
    );

    // ── nodes: versions assigned by the store ──
    for id in ["node_1", "node_2"] {
        let n = node(id, "globex", "triage");
        s.apply(A, Mutation::CreateNode(n)).await.unwrap();
    }
    assert_eq!(s.state().nodes.iter().map(|n| n.version).collect::<Vec<_>>(), [1, 2]);

    // ── ontology ──
    s.apply(A, Mutation::ProposeOntology { tenant_id: "globex".into(), elements: vec![element("e_b"), element("e_a")] }).await.unwrap();
    s.apply(A, Mutation::ReviewOntologyElement { id: "e_b".into(), status: Status::Approved }).await.unwrap();
    assert_eq!(
        s.apply(A, Mutation::ReviewOntologyElement { id: "zzz".into(), status: Status::Approved }).await.unwrap_err(),
        StoreError::NotFound("ontology element".into())
    );
    let st = s.state();
    let o = &st.ontologies["globex"];
    assert_eq!(o.version, 2);
    assert_eq!(o.elements.iter().map(|e| (e.id.as_str(), e.status)).collect::<Vec<_>>(), [("e_b", Status::Approved), ("e_a", Status::Proposed)]);

    deletes(s).await;

    // ── concurrent writers: serialized, chain stays intact ──
    let writes = (0..8).map(|i| s.apply("ops", Mutation::CreateTenant(tenant(&format!("burst-{i}")))));
    for r in futures::future::join_all(writes).await {
        r.unwrap();
    }

    // ── audit chain ──
    let log = s.audit(1000).await.unwrap();
    assert_eq!(log.len() as u64, s.state().audit_head);
    assert_eq!(log[0].action, "store.seed");
    assert!(verify_chain(&log).is_ok());
    let actions: Vec<&str> = log.iter().map(|e| e.action.as_str()).collect();
    assert_eq!(actions.iter().filter(|a| **a == "tenant.create").count(), 10);
    for a in ["api_key.revoke", "datasource.delete", "node.delete", "tenant.delete", "tenant.update"] {
        assert!(actions.contains(&a), "{a} is audited");
    }
    assert!(!serde_json::to_string(&log).unwrap().contains("sk-test"));
    assert_eq!(s.audit(3).await.unwrap(), log[log.len() - 3..].to_vec());
    assert_eq!(s.config.load().version, format!("cp-{}", s.state().audit_head));
}

/// Revoke and delete semantics (run inside `suite`, so on both backends).
async fn deletes(s: &Store) {
    let not_found = |what: &str| StoreError::NotFound(what.into());
    let revoke = |tenant: &str, id: &str| Mutation::RevokeApiKey { tenant_id: tenant.into(), id: id.into(), at: del_ts() };

    // ── API key revoke: soft, the row stays, the hash leaves the snapshot ──
    let head = s.state().audit_head;
    assert_eq!(s.apply(A, revoke("acme", "key_g1")).await.unwrap_err(), not_found("api key"), "other tenant's key");
    assert_eq!(s.apply(A, revoke("nobody", "key_g1")).await.unwrap_err(), not_found("tenant"));
    assert_eq!(s.apply(A, revoke("globex", "key_nope")).await.unwrap_err(), not_found("api key"));
    assert_eq!(s.state().audit_head, head, "failed deletes are not audited");
    s.apply(A, revoke("globex", "key_g1")).await.unwrap();
    assert!(s.config.load().tenant_by_key_hash(&"2".repeat(64)).is_none(), "revoked key is out of the snapshot");
    assert_eq!(s.state().api_keys.iter().find(|k| k.id == "key_g1").unwrap().revoked_at, Some(del_ts()));
    assert_eq!(s.apply(A, revoke("globex", "key_g1")).await.unwrap_err(), not_found("api key"), "repeat revoke is 404");
    // A revoked key's hash can never be minted again.
    let reuse = ApiKeyRecord {
        id: "key_g2".into(),
        tenant_id: "globex".into(),
        name: "again".into(),
        prefix: "cal_2222".into(),
        hash: "2".repeat(64),
        created_at: ts(),
        revoked_at: None,
    };
    assert!(matches!(s.apply(A, Mutation::CreateApiKey(reuse)).await, Err(StoreError::Conflict(_))));
    // Config-seeded keys can be revoked too.
    s.apply(A, revoke("acme", "key_cfg_acme_0")).await.unwrap();
    assert!(s.config.load().tenant_by_key_hash(KEY_HASH).is_none());
    let audit = s.audit(1).await.unwrap();
    assert_eq!((audit[0].action.as_str(), audit[0].actor.as_str()), ("api_key.revoke", A));
    assert_eq!(audit[0].tenant_id.as_deref(), Some("acme"));

    // ── datasource delete: tenant-scoped, soft, connection wiped, name freed ──
    let del_ds = |tenant: &str, id: &str| Mutation::DeleteDatasource { tenant_id: tenant.into(), id: id.into(), at: del_ts() };
    assert_eq!(s.apply(A, del_ds("acme", "ds_1")).await.unwrap_err(), not_found("datasource"), "other tenant's datasource");
    s.apply(A, del_ds("globex", "ds_1")).await.unwrap();
    let st = s.state();
    let ds = st.datasources.iter().find(|d| d.id == "ds_1").unwrap();
    assert_eq!((ds.deleted_at, &ds.connection), (Some(del_ts()), &json!({})));
    assert_eq!(s.apply(A, del_ds("globex", "ds_1")).await.unwrap_err(), not_found("datasource"), "repeat delete is 404");
    assert_eq!(
        s.apply(A, Mutation::SetDatasourceStatus { id: "ds_1".into(), status: "introspecting".into() }).await.unwrap_err(),
        not_found("datasource")
    );
    let again = DatasourceRecord {
        id: "ds_3".into(),
        tenant_id: "globex".into(),
        kind: "mongodb".into(),
        name: "sales".into(),
        status: "pending".into(),
        epoch: 0,
        connection: json!({"uri": {"env": "SALES_URI_2"}}),
        deleted_at: None,
    };
    s.apply(A, Mutation::CreateDatasource(again)).await.unwrap();

    // ── node delete: one version, tenant-scoped; versions are not reused ──
    let del_node = |tenant: &str, id: &str| Mutation::DeleteNode { tenant_id: tenant.into(), id: id.into(), at: del_ts() };
    assert_eq!(s.apply(A, del_node("acme", "node_2")).await.unwrap_err(), not_found("node"));
    s.apply(A, del_node("globex", "node_2")).await.unwrap();
    assert_eq!(s.apply(A, del_node("globex", "node_2")).await.unwrap_err(), not_found("node"));
    s.apply(A, Mutation::CreateNode(node("node_3", "globex", "triage"))).await.unwrap();
    let st = s.state();
    let live: Vec<(&str, u32)> = st.nodes.iter().filter(|n| n.is_live()).map(|n| (n.id.as_str(), n.version)).collect();
    assert_eq!(live, [("node_1", 1), ("node_3", 3)]);

    // ── tenant delete: tombstone + cascade ──
    s.apply(A, Mutation::CreateTenant(tenant("doomed"))).await.unwrap();
    let dkey = ApiKeyRecord {
        id: "key_d1".into(),
        tenant_id: "doomed".into(),
        name: "ci".into(),
        prefix: "cal_4444".into(),
        hash: "4".repeat(64),
        created_at: ts(),
        revoked_at: None,
    };
    s.apply(A, Mutation::CreateApiKey(dkey)).await.unwrap();
    let byok = ProviderKeyRecord {
        id: "openai".into(),
        tenant_id: "doomed".into(),
        kind: ProviderKind::Openai,
        label: "OpenAI".into(),
        base_url: None,
        trust_tier: TrustTier::T2Contracted,
        last4: Some("1234".into()),
        cache_salt: false,
        created_at: ts(),
        secret: Some(SecretRef::Sealed { sealed: sealed_blob() }),
    };
    s.apply(A, Mutation::CreateProviderKey(byok)).await.unwrap();
    let routes = vec![RouteConfig { intent: "default".into(), models: vec!["ext/gpt".into(), "local/qwen".into()] }];
    s.apply(A, Mutation::SetRoutes { tenant_id: "doomed".into(), routes }).await.unwrap();
    let dds = DatasourceRecord {
        id: "ds_d".into(),
        tenant_id: "doomed".into(),
        kind: "postgres".into(),
        name: "erp".into(),
        status: "pending".into(),
        epoch: 0,
        connection: json!({"password": "hunter2"}),
        deleted_at: None,
    };
    s.apply(A, Mutation::CreateDatasource(dds)).await.unwrap();
    s.apply(A, Mutation::CreateNode(node("node_d", "doomed", "triage"))).await.unwrap();
    s.apply(A, Mutation::ProposeOntology { tenant_id: "doomed".into(), elements: vec![element("e_d")] }).await.unwrap();
    assert!(s.config.load().tenant(&"doomed".into()).is_some());

    let del_tenant = |id: &str| Mutation::DeleteTenant { id: id.into(), at: del_ts() };
    assert_eq!(s.apply(A, del_tenant("nobody")).await.unwrap_err(), not_found("tenant"));
    s.apply(A, del_tenant("doomed")).await.unwrap();
    let st = s.state();
    let t = st.tenant_record("doomed").unwrap();
    assert_eq!((t.status, t.deleted_at), (TenantStatus::Deleted, Some(del_ts())));
    assert!(st.tenant("doomed").is_none() && !st.has_tenant("doomed"));
    assert_eq!(st.api_keys.iter().find(|k| k.id == "key_d1").unwrap().revoked_at, Some(del_ts()));
    assert!(st.provider_keys.iter().all(|p| p.tenant_id != "doomed"), "BYOK credentials destroyed");
    assert!(!st.routes.contains_key("doomed"));
    let ds = st.datasources.iter().find(|d| d.id == "ds_d").unwrap();
    assert_eq!((ds.deleted_at, &ds.connection), (Some(del_ts()), &json!({})));
    assert_eq!(st.nodes.iter().find(|n| n.id == "node_d").unwrap().deleted_at, Some(del_ts()));
    // Gone from the data plane: no tenant, no key.
    let snap = s.config.load();
    assert!(snap.tenant(&"doomed".into()).is_none());
    assert!(snap.tenant_by_key_hash(&"4".repeat(64)).is_none());
    assert!(snap.config.tenants.iter().all(|t| t.id.as_str() != "doomed"));
    // The audit row lists what went, without secrets.
    let a = &s.audit(1).await.unwrap()[0];
    assert_eq!((a.action.as_str(), a.target.as_deref(), a.actor.as_str()), ("tenant.delete", Some("doomed"), A));
    assert_eq!(
        a.detail,
        json!({"api_keys_revoked": ["key_d1"], "provider_keys_destroyed": ["openai"], "routes_removed": ["default"],
               "datasources_deleted": ["ds_d"], "nodes_deleted": ["node_d"]})
    );
    // Everything tenant-scoped now 404s; the id cannot be reused; a repeat delete is 404.
    assert_eq!(s.apply(A, del_tenant("doomed")).await.unwrap_err(), not_found("tenant"));
    assert_eq!(s.apply(A, revoke("doomed", "key_d1")).await.unwrap_err(), not_found("tenant"));
    let k5 = ApiKeyRecord { id: "key_d2".into(), tenant_id: "doomed".into(), hash: "5".repeat(64), ..ApiKeyRecord::clone(&st.api_keys[0]) };
    assert_eq!(s.apply(A, Mutation::CreateApiKey(k5)).await.unwrap_err(), not_found("tenant"));
    assert_eq!(s.apply(A, Mutation::CreateNode(node("node_x", "doomed", "x"))).await.unwrap_err(), not_found("tenant"));
    assert_eq!(
        s.apply(A, Mutation::ReviewOntologyElement { id: "e_d".into(), status: Status::Approved }).await.unwrap_err(),
        not_found("ontology element")
    );
    assert_eq!(
        s.apply(A, Mutation::CreateTenant(tenant("doomed"))).await.unwrap_err(),
        StoreError::Conflict("tenant id 'doomed' belonged to a deleted tenant and cannot be reused".into())
    );
}

/// Backend-independent view of the state (no timestamps of seeded rows).
fn normalize(st: &State) -> Value {
    fn strip(v: &mut Value) {
        match v {
            Value::Object(m) => {
                m.remove("created_at");
                m.values_mut().for_each(strip);
            }
            Value::Array(a) => a.iter_mut().for_each(strip),
            _ => {}
        }
    }
    // Sorted: the concurrent burst commits in a nondeterministic order.
    let mut tenants: Vec<Value> = st.tenants.iter().map(|t| json!([t, t.settings])).collect();
    tenants.sort_by_key(|v| v[0]["id"].as_str().unwrap_or_default().to_owned());
    let mut v = json!({
        "tenants": tenants,
        "api_keys": st.api_keys.iter().map(|k| json!([k, k.hash])).collect::<Vec<_>>(),
        "provider_keys": st.provider_keys.iter().map(|p| json!([p, p.secret])).collect::<Vec<_>>(),
        "shared_providers": st.shared_providers,
        "models": st.models,
        "routes": st.routes,
        "datasources": st.datasources.iter().map(|d| json!([d, d.connection])).collect::<Vec<_>>(),
        "nodes": st.nodes,
        "ontologies": st.ontologies,
        "audit_head": st.audit_head,
    });
    strip(&mut v);
    v
}

#[tokio::test]
async fn memory_backend_behaviour() {
    let cfg = base();
    let s = Store::new(cfg.clone(), handle(&cfg), RecentUsage::default());
    assert_eq!(s.backend_name(), "memory");
    suite(&s).await;
}

#[tokio::test]
async fn modelled_tenant_fields_win_over_settings() {
    // `settings` carries TenantConfig fields this crate does not model (e.g. quotas) through to the
    // snapshot, but can never override the fields the store owns.
    let cfg = base();
    let mut st = State::from_config(&cfg);
    st.tenants[0].settings.insert("pii_mode".into(), json!("off")); // modelled fields win
    st.tenants[0].settings.insert("pii_surrogate_scope".into(), json!("session"));
    let out = render(&cfg, &st).unwrap();
    assert_eq!(out.tenants[0].pii_mode, Some(PiiMode::Mask));
    assert_eq!(out.tenants[0].pii_surrogate_scope, PiiSurrogateScope::Tenant);
}

#[test]
fn surrogate_scope_from_the_config_file_is_seeded() {
    let cfg = Config::from_toml_str(&BASE.replace("pii_mode = \"mask\"", "pii_mode = \"mask\"\npii_surrogate_scope = \"session\"")).unwrap();
    let st = State::from_config(&cfg);
    assert_eq!(st.tenants[0].pii_surrogate_scope, PiiSurrogateScope::Session);
    assert!(st.tenants[0].settings.get("pii_surrogate_scope").is_none(), "modelled, not passed through");
    assert_eq!(render(&cfg, &st).unwrap().tenants[0].pii_surrogate_scope, PiiSurrogateScope::Session);
}

#[test]
fn semantic_cache_from_the_config_file_is_seeded() {
    let cfg = Config::from_toml_str(&BASE.replace("pii_mode = \"mask\"", "pii_mode = \"mask\"\nsemantic_cache = \"on\"")).unwrap();
    let st = State::from_config(&cfg);
    assert_eq!(st.tenants[0].semantic_cache, SemanticCacheMode::On);
    assert!(st.tenants[0].settings.get("semantic_cache").is_none(), "modelled, not passed through");
    assert_eq!(render(&cfg, &st).unwrap().tenants[0].semantic_cache, SemanticCacheMode::On);
}

#[test]
fn every_migration_file_is_embedded() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations");
    let mut files: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(".sql"))
        .collect();
    files.sort();
    let embedded: Vec<String> = MIGRATIONS.iter().map(|(v, n, _)| format!("{v:04}_{n}.sql")).collect();
    assert_eq!(files, embedded);
}

#[tokio::test]
async fn postgres_backend_matches_memory_and_persists() {
    let Some(pg) = pg_backend().await else {
        eprintln!("CALIBAN_TEST_DATABASE_URL not set; skipping Postgres store tests");
        return;
    };
    let pool = pg.pool().clone();
    let cfg = base();
    let s = Store::open_postgres(pg, cfg.clone(), handle(&cfg), RecentUsage::default()).await.unwrap();
    assert_eq!(s.backend_name(), "postgres");
    suite(&s).await;

    // Same behaviour as memory: identical final state.
    let mem = Store::new(cfg.clone(), handle(&cfg), RecentUsage::default());
    suite(&mem).await;
    assert_eq!(normalize(&s.state()), normalize(&mem.state()));

    // Restart: migrations are idempotent, the file does not re-seed (DB is the source of truth),
    // and the reloaded state equals the cached one.
    let pg2 = PgBackend::connect_with(pool.connect_options().as_ref().clone()).await.unwrap();
    assert!(pg2.migrate().await.unwrap().is_empty());
    let other_file = Config::from_toml_str(&BASE.replace("name = \"Acme\"", "name = \"Renamed\"")).unwrap();
    let s2 = Store::open_postgres(pg2, other_file.clone(), handle(&other_file), RecentUsage::default()).await.unwrap();
    assert_eq!(s2.state().tenant("acme").unwrap().name, "Acme");
    assert_eq!(normalize(&s2.state()), normalize(&s.state()));
    assert!(verify_chain(&s2.audit(1000).await.unwrap()).is_ok());

    // Another replica's commit is picked up by refresh().
    s2.apply("replica-2", Mutation::CreateTenant(tenant("initech"))).await.unwrap();
    assert!(!s.state().has_tenant("initech"));
    assert!(s.refresh().await.unwrap());
    assert!(s.state().has_tenant("initech"));
    assert_eq!(s.config.load().version, s2.config.load().version);

    // The audit table is append-only at the database level.
    assert!(sqlx::query("UPDATE audit_log SET actor = 'mallory' WHERE seq = 2").execute(&pool).await.is_err());
    assert!(sqlx::query("DELETE FROM audit_log WHERE seq = 2").execute(&pool).await.is_err());

    // Secrets at rest: sealed_key holds ciphertext only.
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM provider_credential WHERE sealed_key IS NOT NULL AND secret_ref IS NULL")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1);

    // Deletes at rest: rows kept for audit, secrets gone, tombstones final.
    let scalar = |sql: &'static str| {
        let pool = pool.clone();
        async move { sqlx::query_scalar::<_, i64>(sql).fetch_one(&pool).await.unwrap() }
    };
    assert_eq!(scalar("SELECT count(*) FROM api_key WHERE id IN ('key_g1', 'key_d1', 'key_cfg_acme_0') AND revoked_at IS NOT NULL").await, 3);
    assert_eq!(scalar("SELECT count(*) FROM tenant WHERE id = 'doomed' AND status = 'deleted' AND deleted_at IS NOT NULL").await, 1);
    assert_eq!(scalar("SELECT count(*) FROM provider_credential WHERE tenant_id = 'doomed'").await, 0, "BYOK ciphertext destroyed");
    assert_eq!(scalar("SELECT count(*) FROM route WHERE tenant_id = 'doomed'").await, 0);
    assert_eq!(scalar("SELECT count(*) FROM datasource WHERE id IN ('ds_1', 'ds_d') AND deleted_at IS NOT NULL AND connection = '{}'").await, 2);
    assert_eq!(scalar("SELECT count(*) FROM node WHERE id IN ('node_2', 'node_d') AND deleted_at IS NOT NULL").await, 2);
    assert_eq!(scalar("SELECT count(*) FROM audit_log WHERE tenant_id = 'doomed'").await, 8, "audit rows of a deleted tenant are kept");
    assert!(sqlx::query("UPDATE api_key SET revoked_at = NULL WHERE id = 'key_g1'").execute(&pool).await.is_err());
    assert!(sqlx::query("UPDATE tenant SET status = 'active', deleted_at = NULL WHERE id = 'doomed'").execute(&pool).await.is_err());
    assert!(sqlx::query("UPDATE datasource SET deleted_at = NULL WHERE id = 'ds_1'").execute(&pool).await.is_err());
    assert!(sqlx::query("UPDATE node SET deleted_at = NULL WHERE id = 'node_2'").execute(&pool).await.is_err());
    // Live datasource names stay unique per tenant at the database level too.
    assert!(
        sqlx::query("INSERT INTO datasource (id, tenant_id, kind, name, connection) VALUES ('ds_dup', 'globex', 'mongodb', 'sales', '{}')")
            .execute(&pool)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn postgres_usage_events_carry_cache_tier_and_usage_source() {
    let Some(pg) = pg_backend().await else { return };
    pg.migrate().await.unwrap();
    let mut e: caliban_meter::UsageEvent = serde_json::from_value(json!({
        "request_id": "req_1", "tenant_id": "acme", "model": "ext/gpt", "intent": "chat", "prompt_tokens": 160,
        "completion_tokens": 5, "cached_prompt_tokens": 100, "cache_write_tokens": 50, "cache_write_1h_tokens": 30,
        "tokens_saved": 0, "cache": "miss", "usage_source": "provider", "pii_entities": 1, "cost_usd": 0.00039,
        "latency_ms": 12, "ts": "2026-10-09T12:00:00Z", "requested_model": "caliban/auto", "intent_confidence": 0.9,
        "route_stage": "knn", "routed_model_cost_usd": 0.00039, "flat_price_usd": 0.0005
    }))
    .unwrap();
    let mut hit = e.clone();
    hit.request_id = "req_2".into();
    hit.cache = caliban_types::CacheStatus::Hit;
    hit.cache_tier = Some(caliban_types::CacheTier::Semantic);
    hit.usage_source = None;
    assert_eq!(pg.insert_usage_events(&[e.clone(), hit]).await.unwrap(), 2);
    e.prompt_tokens = 1;
    assert_eq!(pg.insert_usage_events(&[e]).await.unwrap(), 0, "idempotent on request_id");
    type Row = (String, Option<String>, Option<String>, i64, i64, i64);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT request_id, cache_tier, usage_source, cache_write_tokens, cache_write_1h_tokens, prompt_tokens FROM usage_event ORDER BY request_id",
    )
    .fetch_all(pg.pool())
    .await
    .unwrap();
    assert_eq!(rows, vec![
        ("req_1".into(), None, Some("provider".into()), 50, 30, 160),
        ("req_2".into(), Some("semantic".into()), None, 50, 30, 160),
    ]);
    // The CHECK constraints reject unknown values.
    assert!(sqlx::query("UPDATE usage_event SET usage_source = 'guess' WHERE request_id = 'req_1'").execute(pg.pool()).await.is_err());
    assert!(sqlx::query("UPDATE usage_event SET cache_tier = 'other' WHERE request_id = 'req_1'").execute(pg.pool()).await.is_err());
}

#[tokio::test]
async fn postgres_rejects_edited_migrations() {
    let Some(pg) = pg_backend().await else { return };
    pg.migrate().await.unwrap();
    sqlx::query("UPDATE caliban_schema_migrations SET checksum = 'x' WHERE version = 2").execute(pg.pool()).await.unwrap();
    assert!(pg.migrate().await.unwrap_err().to_string().contains("modified"));
}
