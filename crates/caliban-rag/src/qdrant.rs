//! [`VectorIndex`] on Qdrant over its REST API (port 6333), with `reqwest`, like the semantic
//! cache (`caliban-cache`): no gRPC stack in the binary.
//!
//! Each RAG collection is one Qdrant collection (`{prefix}_{collection id}`) with a named dense
//! vector `dense` (cosine) and a named sparse vector `sparse` with the `idf` modifier (BM25, see
//! [`crate::sparse`]). Payload indexes on `state`, `kind`, `doc_key`, `parent`, `doc_version`,
//! `valid_from` and `valid_to`. A search sends both legs in one `query/batch` call; fusion is done
//! by the caller (RRF, k = 60) so the in-memory index and Qdrant rank the same way.
//!
//! Filtered searches: Qdrant before v1.19.2 could return no results when the HNSW entry point did
//! not satisfy the filter. Every search here is filtered (`state = ready`), so run v1.19.2 or later
//! in production; small collections are searched exactly and are not affected.

use crate::index::{
    Filter, Hit, IndexError, Point, PointKind, PointPayload, PointState, SearchRequest, SearchResponse, VectorIndex,
};
use async_trait::async_trait;
use parking_lot::Mutex;
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::time::Duration;

pub struct QdrantIndex {
    http: reqwest::Client,
    base: String,
    api_key: Option<String>,
    ready: Mutex<HashSet<String>>,
}

impl QdrantIndex {
    /// `url`: the REST endpoint, e.g. `http://qdrant:6333`.
    pub fn new(url: &str, api_key: Option<String>) -> Result<Self, IndexError> {
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(1000))
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(90))
            .build()
            .map_err(|e| IndexError::Backend(e.to_string()))?;
        Ok(Self { http, base: url.trim_end_matches('/').to_owned(), api_key, ready: Mutex::new(HashSet::new()) })
    }

    fn req(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let r = self.http.request(method, format!("{}{path}", self.base));
        match &self.api_key {
            Some(k) => r.header("api-key", k),
            None => r,
        }
    }

    async fn send(&self, rb: reqwest::RequestBuilder) -> Result<(StatusCode, Value), IndexError> {
        let resp = rb.send().await.map_err(|e| IndexError::Unavailable(e.to_string()))?;
        let status = resp.status();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        Ok((status, body))
    }

    async fn ok(&self, rb: reqwest::RequestBuilder, what: &str) -> Result<Value, IndexError> {
        let (status, body) = self.send(rb).await?;
        if status.is_success() {
            Ok(body)
        } else if status.is_server_error() {
            Err(IndexError::Unavailable(format!("{what}: {status}: {}", short(&body))))
        } else {
            Err(IndexError::Backend(format!("{what}: {status}: {}", short(&body))))
        }
    }
}

fn short(v: &Value) -> String {
    v.to_string().chars().take(300).collect()
}

fn kind_str(k: PointKind) -> &'static str {
    match k {
        PointKind::Chunk => "chunk",
        PointKind::Nav => "nav",
    }
}

/// The Qdrant filter for [`Filter`].
pub fn filter_json(f: &Filter) -> Value {
    let state = if f.pending { PointState::Pending } else { PointState::Ready };
    let kinds: Vec<&str> =
        if f.kinds.is_empty() { vec!["chunk"] } else { f.kinds.iter().map(|k| kind_str(*k)).collect() };
    let mut must = vec![
        json!({"key": "state", "match": {"value": state.as_str()}}),
        json!({"key": "kind", "match": {"any": kinds}}),
    ];
    if !f.doc_keys.is_empty() {
        must.push(json!({"key": "doc_key", "match": {"any": f.doc_keys}}));
    }
    if !f.parents.is_empty() {
        must.push(json!({"key": "parent", "match": {"any": f.parents}}));
    }
    if f.roots_only {
        must.push(json!({"is_empty": {"key": "parent"}}));
    }
    if let Some(now) = f.now {
        must.push(
            json!({"should": [{"is_empty": {"key": "valid_from"}}, {"key": "valid_from", "range": {"lte": now}}]}),
        );
        must.push(json!({"should": [{"is_empty": {"key": "valid_to"}}, {"key": "valid_to", "range": {"gt": now}}]}));
    }
    let mut out = json!({"must": must});
    if let Some(k) = &f.exclude_doc_key {
        out["must_not"] = json!([{"key": "doc_key", "match": {"value": k}}]);
    }
    out
}

fn doc_filter(doc_key: &str, version: Option<u32>) -> Value {
    let mut must = vec![json!({"key": "doc_key", "match": {"value": doc_key}})];
    if let Some(v) = version {
        must.push(json!({"key": "doc_version", "match": {"value": v}}));
    }
    json!({"must": must})
}

fn hits(points: &Value) -> Vec<Hit> {
    points
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| {
            let id = match p.get("id")? {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            #[allow(clippy::cast_possible_truncation)]
            let score = p.get("score").and_then(Value::as_f64).unwrap_or(0.0) as f32;
            let payload: PointPayload = serde_json::from_value(p.get("payload")?.clone()).ok()?;
            let dense = p.pointer("/vector/dense").and_then(|v| serde_json::from_value::<Vec<f32>>(v.clone()).ok());
            Some(Hit { id, score, payload, dense })
        })
        .collect()
}

#[async_trait]
impl VectorIndex for QdrantIndex {
    fn name(&self) -> &'static str {
        "qdrant"
    }

    async fn ensure(&self, collection: &str, dim: usize) -> Result<(), IndexError> {
        if self.ready.lock().contains(collection) {
            return Ok(());
        }
        let path = format!("/collections/{collection}");
        let (status, body) = self.send(self.req(reqwest::Method::GET, &path)).await?;
        if status == StatusCode::NOT_FOUND {
            let body = json!({
                "vectors": {"dense": {"size": dim, "distance": "Cosine"}},
                "sparse_vectors": {"sparse": {"modifier": "idf"}},
            });
            let (status, body) = self.send(self.req(reqwest::Method::PUT, &path).json(&body)).await?;
            // 409: another worker created it first.
            if !status.is_success() && status != StatusCode::CONFLICT {
                return Err(IndexError::Backend(format!("create {collection}: {status}: {}", short(&body))));
            }
            for (field, schema) in [
                ("state", "keyword"),
                ("kind", "keyword"),
                ("doc_key", "keyword"),
                ("parent", "keyword"),
                ("tenant_id", "keyword"),
                ("doc_version", "integer"),
                ("valid_from", "integer"),
                ("valid_to", "integer"),
            ] {
                let idx = json!({"field_name": field, "field_schema": schema});
                self.ok(self.req(reqwest::Method::PUT, &format!("{path}/index?wait=true")).json(&idx), "payload index")
                    .await?;
            }
        } else if status.is_success() {
            let have = body.pointer("/result/config/params/vectors/dense/size").and_then(Value::as_u64);
            if have.is_some_and(|h| h != dim as u64) {
                return Err(IndexError::Backend(format!(
                    "collection {collection} holds {}-d vectors, not {dim} (was the embedding model changed?)",
                    have.unwrap_or_default()
                )));
            }
        } else {
            return Err(IndexError::Unavailable(format!("get {collection}: {status}")));
        }
        self.ready.lock().insert(collection.to_owned());
        Ok(())
    }

    async fn upsert(&self, collection: &str, points: &[Point]) -> Result<(), IndexError> {
        let points: Vec<Value> = points
            .iter()
            .map(|p| {
                let mut vector = json!({"dense": p.dense});
                if !p.sparse.is_empty() {
                    vector["sparse"] = json!({"indices": p.sparse.indices, "values": p.sparse.values});
                }
                json!({"id": p.id, "vector": vector, "payload": p.payload})
            })
            .collect();
        let path = format!("/collections/{collection}/points?wait=true");
        self.ok(self.req(reqwest::Method::PUT, &path).json(&json!({"points": points})), "upsert").await.map(|_| ())
    }

    async fn set_state(
        &self,
        collection: &str,
        doc_key: &str,
        version: u32,
        state: PointState,
    ) -> Result<(), IndexError> {
        let body = json!({"payload": {"state": state.as_str()}, "filter": doc_filter(doc_key, Some(version))});
        let path = format!("/collections/{collection}/points/payload?wait=true");
        self.ok(self.req(reqwest::Method::POST, &path).json(&body), "set state").await.map(|_| ())
    }

    async fn delete_doc(&self, collection: &str, doc_key: &str, version: Option<u32>) -> Result<(), IndexError> {
        let body = json!({"filter": doc_filter(doc_key, version)});
        let path = format!("/collections/{collection}/points/delete?wait=true");
        let (status, v) = self.send(self.req(reqwest::Method::POST, &path).json(&body)).await?;
        if status.is_success() || status == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(IndexError::Backend(format!("delete: {status}: {}", short(&v))))
        }
    }

    async fn drop_collection(&self, collection: &str) -> Result<(), IndexError> {
        self.ready.lock().remove(collection);
        let (status, v) = self.send(self.req(reqwest::Method::DELETE, &format!("/collections/{collection}"))).await?;
        if status.is_success() || status == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(IndexError::Backend(format!("drop {collection}: {status}: {}", short(&v))))
        }
    }

    async fn search(&self, collection: &str, req: &SearchRequest) -> Result<SearchResponse, IndexError> {
        let filter = filter_json(&req.filter);
        let with_vector = if req.with_vectors { json!(["dense"]) } else { json!(false) };
        let mut searches = Vec::new();
        let mut legs = Vec::new();
        if let Some(d) = &req.dense {
            searches.push(json!({"query": d, "using": "dense", "filter": filter, "limit": req.limit,
                                 "with_payload": true, "with_vector": with_vector}));
            legs.push(true);
        }
        if let Some(s) = req.sparse.as_ref().filter(|s| !s.is_empty()) {
            searches.push(json!({"query": {"indices": s.indices, "values": s.values}, "using": "sparse",
                                 "filter": filter, "limit": req.limit, "with_payload": true,
                                 "with_vector": with_vector}));
            legs.push(false);
        }
        if searches.is_empty() {
            return Ok(SearchResponse::default());
        }
        let path = format!("/collections/{collection}/points/query/batch");
        let (status, v) =
            self.send(self.req(reqwest::Method::POST, &path).json(&json!({"searches": searches}))).await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(SearchResponse::default());
        }
        if !status.is_success() {
            let e = format!("query: {status}: {}", short(&v));
            return Err(if status.is_server_error() { IndexError::Unavailable(e) } else { IndexError::Backend(e) });
        }
        let mut out = SearchResponse::default();
        for (i, dense) in legs.into_iter().enumerate() {
            let points = v.pointer(&format!("/result/{i}/points")).cloned().unwrap_or(Value::Null);
            let h = hits(&points);
            if dense {
                out.dense = h;
            } else {
                out.sparse = h;
            }
        }
        Ok(out)
    }

    async fn count(&self, collection: &str) -> Result<usize, IndexError> {
        let path = format!("/collections/{collection}/points/count");
        let (status, v) = self.send(self.req(reqwest::Method::POST, &path).json(&json!({"exact": true}))).await?;
        if status == StatusCode::NOT_FOUND {
            return Ok(0);
        }
        if !status.is_success() {
            return Err(IndexError::Backend(format!("count: {status}: {}", short(&v))));
        }
        Ok(usize::try_from(v.pointer("/result/count").and_then(Value::as_u64).unwrap_or(0)).unwrap_or(usize::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_always_require_readiness() {
        let f = filter_json(&Filter::default());
        assert_eq!(f["must"][0], json!({"key": "state", "match": {"value": "ready"}}));
        assert_eq!(f["must"][1], json!({"key": "kind", "match": {"any": ["chunk"]}}));
        let f = filter_json(&Filter {
            doc_keys: vec!["k".into()],
            exclude_doc_key: Some("x".into()),
            now: Some(10),
            ..Filter::default()
        });
        assert_eq!(f["must"].as_array().unwrap().len(), 5);
        assert_eq!(f["must_not"][0]["match"]["value"], "x");
    }
}
