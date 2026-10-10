//! The built-in datasource tool (`builtin://datasource_query`, P3 M4): read-only queries over the
//! tenant's datasources through the CQIR lanes.
//!
//! The model writes a CQIR query (ontology ids only; never a collection, a path or an operator).
//! Before anything runs:
//! - every entity the query touches (its metrics' grains, its dimensions' and filters'
//!   attributes, resolved to their root entity) must be inside the calling node's
//!   `datasources.scopes` **and** the invoking API key's datasource scopes (when the key has any):
//!   `<datasource>.<collection or entity name or *>:read`;
//! - an entity with a row-level policy is refused: its predicate needs a user principal, which a
//!   node run (an API key) does not have, so the tool fails closed rather than read unfiltered rows;
//! - the query is validated and compiled against the approved ontology (the deterministic CQIR
//!   compiler), and lowered for the native lane.
//!
//! The rows come back capped and, like any tool result, anonymized and labelled `datasource` by
//! the executor. The native MongoDB lane executes ([`MongoLane`]); other datasource kinds are
//! refused until their lane exists.

use caliban_config::{ConfigHandle, DatasourceConfig, Keyring, TenantConfig};
use caliban_nodes::executor::{Tool, ToolCtx, ToolError, ToolInfo, ToolRegistry};
use caliban_ontology::compile::mongo::{MongoQuery, NativeOptions};
use caliban_ontology::model::EntityBinding;
use caliban_ontology::{Model, Ontology};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

/// Rows a query returns at most.
pub const ROW_CAP: usize = 200;

/// Runs a lowered query against a datasource (credentials opened).
#[async_trait::async_trait]
pub trait DatasourceLane: Send + Sync {
    async fn run(&self, tenant: &str, ds: &DatasourceConfig, q: &MongoQuery) -> Result<Value, String>;
}

/// Built-in tools, from the snapshot.
pub struct Builtins {
    config: ConfigHandle,
    keyring: Arc<Keyring>,
    lane: Arc<dyn DatasourceLane>,
}

impl Builtins {
    pub fn new(config: ConfigHandle, keyring: Arc<Keyring>, lane: Arc<dyn DatasourceLane>) -> Self {
        Self { config, keyring, lane }
    }
}

impl ToolRegistry for Builtins {
    fn resolve(&self, _tenant: &str, reference: &str) -> Result<Arc<dyn Tool>, ToolError> {
        match reference {
            "builtin://datasource_query" => Ok(Arc::new(DatasourceQuery {
                config: self.config.clone(),
                keyring: Arc::clone(&self.keyring),
                lane: Arc::clone(&self.lane),
            })),
            other => Err(ToolError::UnknownKind(other.to_owned())),
        }
    }
}

pub struct DatasourceQuery {
    config: ConfigHandle,
    keyring: Arc<Keyring>,
    lane: Arc<dyn DatasourceLane>,
}

/// A scope `<datasource>.<object>:<access>`.
fn parse_scope(s: &str) -> Option<(String, String, String)> {
    let (target, access) = s.rsplit_once(':')?;
    let (ds, object) = target.split_once('.')?;
    Some((ds.to_ascii_lowercase(), object.to_owned(), access.to_owned()))
}

/// Read scopes the run may use: the node's, narrowed to the key's when it has any.
fn effective_scopes(t: &TenantConfig, ctx: &ToolCtx) -> Vec<(String, String)> {
    let key = ctx.invoker_key_hash.as_ref().and_then(|h| t.api_key_datasource_scopes.get(h));
    let read = |v: &[String]| -> Vec<(String, String)> {
        v.iter().filter_map(|s| parse_scope(s)).filter(|(_, _, a)| a == "read").map(|(d, o, _)| (d, o)).collect()
    };
    let node = read(&ctx.datasource_scopes);
    match key {
        None => node,
        Some(k) => {
            let k = read(k);
            // A pair is allowed when both sides allow it ("*" matches any object).
            let covers = |set: &[(String, String)], d: &str, o: &str| {
                set.iter().any(|(sd, so)| sd == d && (so == "*" || so == o))
            };
            let mut out = Vec::new();
            for (d, o) in &node {
                for (kd, ko) in &k {
                    if d != kd {
                        continue;
                    }
                    let pair = if o == "*" { (d.clone(), ko.clone()) } else { (d.clone(), o.clone()) };
                    if covers(&node, &pair.0, &pair.1) && covers(&k, &pair.0, &pair.1) && !out.contains(&pair) {
                        out.push(pair);
                    }
                }
            }
            out
        }
    }
}

/// The root entities a query touches.
fn touched(model: &Model, q: &caliban_ontology::cqir::Query) -> Result<BTreeSet<String>, String> {
    let mut entities = BTreeSet::new();
    let mut add_attr = |id: &str| -> Result<(), String> {
        let a = model.attributes.get(id).ok_or_else(|| format!("unknown attribute '{id}'"))?;
        entities.insert(a.entity.clone());
        Ok(())
    };
    for d in &q.dimensions {
        add_attr(&d.id)?;
    }
    for f in &q.filters {
        add_attr(&f.attr)?;
    }
    let mut out = BTreeSet::new();
    for m in &q.metrics {
        let def = model.metrics.get(&m.id).ok_or_else(|| format!("unknown metric '{}'", m.id))?;
        out.insert(def.grain.clone());
    }
    out.extend(entities);
    out.into_iter()
        .map(|e| model.root_of(&e).map(str::to_owned).ok_or_else(|| format!("entity '{e}' has no root entity")))
        .collect()
}

impl DatasourceQuery {
    fn tenant(&self, tenant: &str) -> Result<TenantConfig, ToolError> {
        let snap = self.config.load();
        snap.tenant(&tenant.into()).cloned().ok_or_else(|| ToolError::Failed("unknown tenant".into()))
    }

    fn model(t: &TenantConfig) -> Result<Model, ToolError> {
        let o: Ontology = t
            .ontology
            .clone()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|e| ToolError::Failed(format!("the ontology cannot be read: {e}")))?
            .ok_or_else(|| ToolError::Failed("the tenant has no approved ontology".into()))?;
        Ok(Model::from_ontology(&o))
    }

    /// Validates, checks scopes and policies, and lowers the query. Returns the datasource and the
    /// native-lane query.
    pub fn plan(&self, ctx: &ToolCtx, args: &Value) -> Result<(DatasourceConfig, MongoQuery), ToolError> {
        let fail = |m: String| ToolError::Failed(m);
        let t = self.tenant(&ctx.tenant)?;
        let model = Self::model(&t)?;
        let query: caliban_ontology::cqir::Query =
            serde_json::from_value(args.get("query").cloned().unwrap_or(Value::Null))
                .map_err(|e| fail(format!("query is not a CQIR query: {e}")))?;
        let allowed = effective_scopes(&t, ctx);
        for root in touched(&model, &query).map_err(fail)? {
            let EntityBinding::Root { datasource, collection, .. } =
                &model.entities.get(&root).ok_or_else(|| fail(format!("unknown entity '{root}'")))?.binding
            else {
                return Err(fail(format!("entity '{root}' is not a root entity")));
            };
            let ds = t
                .datasources
                .iter()
                .find(|d| &d.id == datasource || d.name.eq_ignore_ascii_case(datasource))
                .ok_or_else(|| fail(format!("entity '{root}' is bound to an unknown datasource")))?;
            let ok = allowed
                .iter()
                .any(|(d, o)| d.eq_ignore_ascii_case(&ds.name) && (o == "*" || o == collection || o == &root));
            if !ok {
                return Err(fail(format!(
                    "'{root}' ({}.{collection}) is outside the datasource scopes of this node and API key",
                    ds.name
                )));
            }
            if model.policies.iter().any(|p| p.entity == root && p.row_filter.is_some()) {
                return Err(fail(format!(
                    "'{root}' has a row-level policy, which needs a user principal; node runs cannot read it"
                )));
            }
        }
        let plan = caliban_ontology::compile::plan(&model, &query, &[]).map_err(|e| fail(e.to_string()))?;
        let audit = format!("caliban:node:{}:{}", ctx.run_id, ctx.step_id);
        let opts = NativeOptions { audit_id: &audit, ..NativeOptions::default() };
        let mq = caliban_ontology::compile::mongo::lower(&model, &plan, &opts).map_err(|e| fail(e.to_string()))?;
        let ds = t
            .datasources
            .iter()
            .find(|d| d.id == mq.datasource || d.name.eq_ignore_ascii_case(&mq.datasource))
            .cloned()
            .ok_or_else(|| fail("the query's datasource is not available".into()))?;
        Ok((ds, mq))
    }
}

#[async_trait::async_trait]
impl Tool for DatasourceQuery {
    fn info(&self) -> ToolInfo {
        ToolInfo {
            name: "datasource_query".into(),
            description: "Runs a read-only query over the tenant's approved ontology. Write the query in CQIR: \
                          ontology ids only (metrics, dimensions, filters, order_by, limit, ontology_version). \
                          Returns the rows (at most 200)."
                .into(),
            input_schema: json!({"type": "object", "required": ["query"],
                                 "properties": {"query": {"type": "object", "description": "A CQIR query"}}}),
        }
    }

    async fn call(&self, ctx: &ToolCtx, args: Value) -> Result<Value, ToolError> {
        let (mut ds, q) = self.plan(ctx, &args)?;
        // Credentials are opened only for the connector, here.
        let t = self.tenant(&ctx.tenant)?;
        let wrapped = t.data_key.clone().ok_or_else(|| ToolError::Failed("the tenant has no data key".into()))?;
        let dek = self.keyring.unwrap_dek(&ctx.tenant, &wrapped).map_err(ToolError::Failed)?;
        ds.connection =
            caliban_config::open_sealed_values(&ds.connection, &ctx.tenant, &dek).map_err(ToolError::Failed)?;
        self.lane.run(&ctx.tenant, &ds, &q).await.map_err(ToolError::Transient)
    }
}

/// The native MongoDB lane (caliban-connect): read-only connectors, cached per datasource.
#[derive(Default)]
pub struct MongoLane {
    connectors: tokio::sync::Mutex<HashMap<(String, String), Arc<caliban_connect::mongo::MongoConnector>>>,
}

#[async_trait::async_trait]
impl DatasourceLane for MongoLane {
    async fn run(&self, tenant: &str, ds: &DatasourceConfig, q: &MongoQuery) -> Result<Value, String> {
        if ds.kind != "mongodb" {
            return Err(format!("datasource kind '{}' has no query lane yet (only mongodb)", ds.kind));
        }
        let key = (tenant.to_owned(), ds.id.clone());
        let conn = {
            let mut cache = self.connectors.lock().await;
            match cache.get(&key) {
                Some(c) => Arc::clone(c),
                None => {
                    let mut cfg: caliban_connect::mongo::MongoConfig =
                        serde_json::from_value(ds.connection.clone()).map_err(|e| format!("connection: {e}"))?;
                    cfg.datasource_id = Some(q.datasource.clone());
                    let c = Arc::new(
                        caliban_connect::mongo::MongoConnector::connect(cfg).await.map_err(|e| e.to_string())?,
                    );
                    // Read-only by construction: a principal that can write is refused.
                    c.verify_read_only().await.map_err(|e| e.to_string())?;
                    cache.insert(key, Arc::clone(&c));
                    c
                }
            }
        };
        let r = conn.execute(q, ROW_CAP).await.map_err(|e| e.to_string())?;
        Ok(json!({"datasource": ds.name, "rows": r.rows, "truncated": r.truncated}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use caliban_config::{Config, Snapshot};
    use std::sync::Mutex;

    /// Records the queries it is asked to run.
    #[derive(Default)]
    struct Fake(Mutex<Vec<(String, MongoQuery, Value)>>);

    #[async_trait::async_trait]
    impl DatasourceLane for Fake {
        async fn run(&self, _tenant: &str, ds: &DatasourceConfig, q: &MongoQuery) -> Result<Value, String> {
            self.0.lock().unwrap().push((ds.name.clone(), q.clone(), ds.connection.clone()));
            Ok(json!({"rows": [{"total": 42}], "truncated": false}))
        }
    }

    fn ontology() -> Value {
        let el = |id: &str, kind: &str, spec: Value| json!({"id": id, "name": id, "status": "approved", "provenance": "human", "kind": kind, "spec": spec});
        json!({"tenant_id": "acme", "version": 3, "elements": [
            el("Order", "entity", json!({"binding": {"type": "root", "datasource": "ds_shop", "collection": "orders"}, "keys": ["_id"]})),
            el("Order.total", "attribute", json!({"entity": "Order", "path": "total", "column": "total", "data_type": "number"})),
            el("Order.status", "attribute", json!({"entity": "Order", "path": "status", "column": "status", "data_type": "string"})),
            el("revenue", "metric", json!({"grain": "Order", "aggregation": "sum", "expr": {"op": "attr", "id": "Order.total"}})),
            el("Patient", "entity", json!({"binding": {"type": "root", "datasource": "ds_shop", "collection": "patients"}, "keys": ["_id"]})),
            el("Patient.age", "attribute", json!({"entity": "Patient", "path": "age", "column": "age", "data_type": "number"})),
            el("patients", "metric", json!({"grain": "Patient", "aggregation": "count", "expr": {"op": "rows"}})),
        ]})
    }

    fn setup(key_scopes: Option<Vec<&str>>) -> (Builtins, Arc<Fake>, Keyring) {
        let ring = Keyring::new([7; 32], []);
        let (dek, wrapped) = {
            let d = caliban_config::Dek::generate();
            let w = ring.wrap_dek("acme", &d);
            (d, w)
        };
        let conn =
            json!({"uri": {"$sealed": dek.seal("acme", "\"mongodb://reader:pw@db:27017\"")}, "database": "shop"});
        let mut t = json!({"id": "acme", "name": "Acme", "api_key_hashes": ["ab".repeat(32)],
            "datasources": [{"id": "ds_shop", "name": "shop", "kind": "mongodb", "connection": conn}],
            "ontology": ontology(), "data_key": wrapped});
        if let Some(s) = key_scopes {
            t["api_key_datasource_scopes"] = json!({"ab".repeat(32): s});
        }
        let mut cfg = Config::from_toml_str("").unwrap();
        cfg.tenants = vec![serde_json::from_value(t).unwrap()];
        let handle = ConfigHandle::new(Snapshot::new(cfg, "t"));
        let fake = Arc::new(Fake::default());
        (Builtins::new(handle, Arc::new(ring.clone()), fake.clone()), fake, ring)
    }

    fn ctx(scopes: &[&str]) -> ToolCtx {
        ToolCtx {
            tenant: "acme".into(),
            node: "report".into(),
            node_version: 1,
            run_id: "run_1".into(),
            datasource_scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
            invoker_key_hash: Some("ab".repeat(32)),
            step_id: "q#0".into(),
            idempotency_key: "k".into(),
        }
    }

    fn query(metric: &str) -> Value {
        json!({"query": {"ir_version": "1", "ontology_version": "acme@3", "metrics": [{"id": metric}]}})
    }

    #[tokio::test]
    async fn queries_run_within_node_and_key_scopes() {
        let (b, fake, _) = setup(None);
        let tool = b.resolve("acme", "builtin://datasource_query").unwrap();
        let out = tool.call(&ctx(&["shop.orders:read"]), query("revenue")).await.unwrap();
        assert_eq!(out["rows"][0]["total"], 42);
        let (name, q, conn) = fake.0.lock().unwrap()[0].clone();
        assert_eq!((name.as_str(), q.collection.as_str()), ("shop", "orders"));
        assert_eq!(conn["uri"], "mongodb://reader:pw@db:27017", "credentials opened for the connector only");
        // Outside the node's scopes.
        let e = tool.call(&ctx(&["shop.orders:read"]), query("patients")).await.unwrap_err();
        assert!(e.to_string().contains("outside the datasource scopes"), "{e}");
        // Write scopes do not grant reads; a wildcard does.
        assert!(tool.call(&ctx(&["shop.orders:write"]), query("revenue")).await.is_err());
        tool.call(&ctx(&["shop.*:read"]), query("patients")).await.unwrap();
        // A stale ontology version is refused by the compiler.
        let mut stale = query("revenue");
        stale["query"]["ontology_version"] = json!("acme@2");
        assert!(tool.call(&ctx(&["shop.*:read"]), stale).await.unwrap_err().to_string().contains("ontology"));
    }

    #[tokio::test]
    async fn the_key_narrows_what_the_node_may_read() {
        let (b, fake, _) = setup(Some(vec!["shop.orders:read"]));
        let tool = b.resolve("acme", "builtin://datasource_query").unwrap();
        tool.call(&ctx(&["shop.*:read"]), query("revenue")).await.unwrap();
        let e = tool.call(&ctx(&["shop.*:read"]), query("patients")).await.unwrap_err();
        assert!(e.to_string().contains("outside the datasource scopes"), "{e}");
        assert_eq!(fake.0.lock().unwrap().len(), 1);
    }
}
