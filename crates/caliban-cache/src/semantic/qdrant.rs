//! Qdrant over its REST API (port 6333), with `reqwest`.
//!
//! REST rather than the official `qdrant-client` crate: that crate speaks gRPC and would pull
//! tonic, prost and a second HTTP/2 stack into the router binary for five calls. The JSON
//! payloads here are small (one vector and one response body); the REST overhead is well inside
//! the lookup budget (see the README for measured latencies).
//!
//! Layout: one collection per embedding model and dimension (`{prefix}_{model}_{dim}`), cosine
//! distance, payload indexes on `tenant_id` (`is_tenant: true`, Qdrant's tiered multitenancy),
//! `partition` and `expires_at`. HNSW is built per tenant (`m = 0`, `payload_m = 16`), as Qdrant
//! recommends for multitenant collections. Every query filters on `tenant_id`.

use super::policy::EntryStats;
use super::store::{Candidate, EntryPayload, SearchQuery, StoreError, VectorStore};
use async_trait::async_trait;
use parking_lot::Mutex;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::time::Duration;

pub struct QdrantStore {
    http: reqwest::Client,
    base: String,
    api_key: Option<String>,
    /// Collections known to exist (created or seen) in this process.
    ready: Mutex<HashSet<String>>,
}

impl QdrantStore {
    /// `url`: the REST endpoint, e.g. `http://qdrant:6333`.
    pub fn new(url: &str, api_key: Option<String>) -> Result<Self, StoreError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(500))
            .timeout(Duration::from_secs(5))
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(Self { http, base: url.trim_end_matches('/').to_owned(), api_key, ready: Mutex::new(HashSet::new()) })
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let r = self.http.request(method, format!("{}{path}", self.base));
        match &self.api_key {
            Some(k) => r.header("api-key", k),
            None => r,
        }
    }

    async fn send(&self, rb: reqwest::RequestBuilder) -> Result<(StatusCode, Value), StoreError> {
        let resp = rb.send().await.map_err(|e| StoreError::Unavailable(e.to_string()))?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        Ok((status, body))
    }

    async fn ok(&self, rb: reqwest::RequestBuilder, what: &str) -> Result<Value, StoreError> {
        let (status, body) = self.send(rb).await?;
        if status.is_success() {
            Ok(body)
        } else {
            Err(StoreError::Backend(format!("{what}: {status}: {}", short(&body))))
        }
    }

    /// Creates the collection and its payload indexes unless this process already saw it.
    async fn ensure(&self, collection: &str, dim: usize) -> Result<(), StoreError> {
        if self.ready.lock().contains(collection) {
            return Ok(());
        }
        let path = format!("/collections/{collection}");
        let (status, _) = self.send(self.req(reqwest::Method::GET, &path)).await?;
        if status == StatusCode::NOT_FOUND {
            let body = json!({
                "vectors": { "size": dim, "distance": "Cosine" },
                "hnsw_config": { "m": 0, "payload_m": 16 },
            });
            let (status, body) = self.send(self.req(reqwest::Method::PUT, &path).json(&body)).await?;
            // 409: another router created it first.
            if !status.is_success() && status != StatusCode::CONFLICT {
                return Err(StoreError::Backend(format!("create {collection}: {status}: {}", short(&body))));
            }
            for (field, schema) in [
                ("tenant_id", json!({"type": "keyword", "is_tenant": true})),
                ("partition", json!("keyword")),
                ("expires_at", json!("integer")),
            ] {
                let idx = json!({ "field_name": field, "field_schema": schema });
                self.ok(self.req(reqwest::Method::PUT, &format!("{path}/index?wait=true")).json(&idx), "create payload index").await?;
            }
        } else if !status.is_success() {
            return Err(StoreError::Backend(format!("get {collection}: {status}")));
        }
        self.ready.lock().insert(collection.to_owned());
        Ok(())
    }
}

fn short(v: &Value) -> String {
    v.to_string().chars().take(300).collect()
}

fn tenant_cond(tenant: &str) -> Value {
    json!({ "key": "tenant_id", "match": { "value": tenant } })
}

#[async_trait]
impl VectorStore for QdrantStore {
    async fn search(&self, q: &SearchQuery<'_>) -> Result<Vec<Candidate>, StoreError> {
        let body = json!({
            "query": q.vector,
            "filter": { "must": [
                tenant_cond(q.tenant),
                { "key": "partition", "match": { "value": q.partition } },
                { "key": "expires_at", "range": { "gt": q.now } },
            ]},
            "limit": q.limit,
            "with_payload": true,
        });
        let path = format!("/collections/{}/points/query", q.collection);
        let (status, v) = self.send(self.req(reqwest::Method::POST, &path).json(&body)).await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(vec![]);
        }
        if !status.is_success() {
            return Err(StoreError::Backend(format!("query: {status}: {}", short(&v))));
        }
        let points = v.pointer("/result/points").and_then(Value::as_array).cloned().unwrap_or_default();
        let mut out = Vec::with_capacity(points.len());
        for p in points {
            let id = match p.get("id") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => continue,
            };
            #[allow(clippy::cast_possible_truncation)]
            let score = p.get("score").and_then(Value::as_f64).unwrap_or(0.0) as f32;
            let Ok(payload) = serde_json::from_value::<EntryPayload>(p.get("payload").cloned().unwrap_or_default()) else { continue };
            // Belt and braces: the filter already guarantees this.
            if payload.tenant_id != q.tenant {
                continue;
            }
            out.push(Candidate { id, score, payload });
        }
        Ok(out)
    }

    async fn upsert(&self, collection: &str, id: &str, vector: &[f32], payload: &EntryPayload) -> Result<(), StoreError> {
        self.ensure(collection, vector.len()).await?;
        let body = json!({ "points": [{ "id": id, "vector": vector, "payload": payload }] });
        let path = format!("/collections/{collection}/points?wait=true");
        match self.ok(self.req(reqwest::Method::PUT, &path).json(&body), "upsert").await {
            Err(e) if e.to_string().contains("404") => {
                // Deleted behind our back: forget it and retry once.
                self.ready.lock().remove(collection);
                self.ensure(collection, vector.len()).await?;
                self.ok(self.req(reqwest::Method::PUT, &path).json(&body), "upsert").await.map(|_| ())
            }
            r => r.map(|_| ()),
        }
    }

    async fn update_stats(&self, collection: &str, tenant: &str, id: &str, stats: &EntryStats, threshold: f32) -> Result<(), StoreError> {
        let body = json!({
            "payload": { "stats": stats, "threshold": threshold },
            "filter": { "must": [ { "has_id": [id] }, tenant_cond(tenant) ] },
        });
        let path = format!("/collections/{collection}/points/payload?wait=true");
        self.ok(self.req(reqwest::Method::POST, &path).json(&body), "set payload").await.map(|_| ())
    }

    async fn delete_expired(&self, collection: &str, now: i64) -> Result<(), StoreError> {
        let body = json!({ "filter": { "must": [ { "key": "expires_at", "range": { "lte": now } } ] } });
        let path = format!("/collections/{collection}/points/delete");
        let (status, v) = self.send(self.req(reqwest::Method::POST, &path).json(&body)).await?;
        if status.is_success() || status == StatusCode::NOT_FOUND { Ok(()) } else { Err(StoreError::Backend(format!("delete expired: {status}: {}", short(&v)))) }
    }

    async fn delete_tenant(&self, collection: &str, tenant: &str) -> Result<(), StoreError> {
        let body = json!({ "filter": { "must": [ tenant_cond(tenant) ] } });
        let path = format!("/collections/{collection}/points/delete?wait=true");
        let (status, v) = self.send(self.req(reqwest::Method::POST, &path).json(&body)).await?;
        if status.is_success() || status == StatusCode::NOT_FOUND { Ok(()) } else { Err(StoreError::Backend(format!("delete tenant: {status}: {}", short(&v)))) }
    }

    async fn list_collections(&self) -> Result<Vec<String>, StoreError> {
        let v = self.ok(self.req(reqwest::Method::GET, "/collections"), "list collections").await?;
        let names = v.pointer("/result/collections").and_then(Value::as_array).cloned().unwrap_or_default();
        Ok(names.iter().filter_map(|c| c.get("name").and_then(Value::as_str).map(str::to_owned)).collect())
    }
}
