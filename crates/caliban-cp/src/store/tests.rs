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

fn tenant(id: &str) -> Tenant {
    Tenant { id: id.into(), name: id.to_uppercase(), region: Some("eu".into()), pii_default: PiiMode::Off, created_at: ts(), settings: Map::new() }
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
    let key = ApiKeyRecord {
        id: "key_g1".into(),
        tenant_id: "globex".into(),
        name: "ci".into(),
        prefix: "cal_2222".into(),
        hash: "2".repeat(64),
        created_at: ts(),
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
        let n = NodeRecord { id: id.into(), tenant_id: "globex".into(), name: "triage".into(), version: 0, spec: json!({"k": 1}), created_at: ts() };
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
    assert_eq!(actions.iter().filter(|a| **a == "tenant.create").count(), 9);
    assert!(!serde_json::to_string(&log).unwrap().contains("sk-test"));
    assert_eq!(s.audit(3).await.unwrap(), log[log.len() - 3..].to_vec());
    assert_eq!(s.config.load().version, format!("cp-{}", s.state().audit_head));
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
    let out = render(&cfg, &st).unwrap();
    assert_eq!(out.tenants[0].pii_mode, Some(PiiMode::Mask));
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
}

#[tokio::test]
async fn postgres_rejects_edited_migrations() {
    let Some(pg) = pg_backend().await else { return };
    pg.migrate().await.unwrap();
    sqlx::query("UPDATE caliban_schema_migrations SET checksum = 'x' WHERE version = 2").execute(pg.pool()).await.unwrap();
    assert!(pg.migrate().await.unwrap_err().to_string().contains("modified"));
}
