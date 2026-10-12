//! Datasource introspection: the ontology bootstrap behind `POST /api/v1/datasources/{id}/introspect`
//! (research note 08, "Schema inference & ontology bootstrap"; note 03, "Bootstrap
//! (LLM-proposed, human-approved)").
//!
//! The job connects with the datasource's own credentials (opened with the tenant's data key),
//! checks the principal is read only, samples every collection (stratified: `$sample`, newest and
//! oldest by `_id`, never natural order), infers the paths, discovers references by probing
//! sampled values against target `_id`s, and turns the snapshot into `proposed` elements
//! (`caliban_connect::bootstrap`): one entity per collection, embedded entities for arrays of
//! documents, attributes, subtypes, reference relations (unverified). They are written as one
//! ontology version; a human approves them through the review API.
//!
//! **What a re-run does.** Element ids are deterministic. A proposal whose element the tenant
//! already reviewed (approved, rejected, deprecated, stale) is skipped: introspection never
//! overwrites a human decision. A proposal identical to the pending one is skipped too, so a
//! re-run that finds nothing new makes no version.
//!
//! **Jobs** are kept by the control plane that runs them (the last 100): `GET
//! /api/v1/datasources/{id}/introspection` answers on that replica. The datasource's `status`
//! (`introspecting`, then `ready` or `failed`) is stored and seen by every replica.
//!
//! The LLM proposal pass (names, descriptions, PII classes from redacted samples) is not part of
//! this job yet: names come from the deterministic rules.

use crate::store::{Mutation, State};
use caliban_connect::SchemaSnapshot;
use caliban_ontology::{Element, Status};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::Arc;

/// How long one introspection may take.
pub const JOB_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
const KEEP_JOBS: usize = 100;

/// Takes a schema snapshot of a datasource (MongoDB in production; a fixed one in tests).
#[async_trait::async_trait]
pub trait Introspector: Send + Sync {
    /// `connection`: the datasource's connection with its secrets opened.
    async fn snapshot(&self, kind: &str, datasource_id: &str, connection: Value) -> Result<SchemaSnapshot, String>;
}

/// The MongoDB lane's introspection (`caliban_connect::mongo`).
pub struct MongoIntrospector;

#[async_trait::async_trait]
impl Introspector for MongoIntrospector {
    async fn snapshot(&self, kind: &str, datasource_id: &str, connection: Value) -> Result<SchemaSnapshot, String> {
        if kind != "mongodb" {
            return Err(format!("datasource kind '{kind}' has no introspection yet (only mongodb)"));
        }
        let mut cfg: caliban_connect::mongo::MongoConfig =
            serde_json::from_value(connection).map_err(|e| format!("connection: {e}"))?;
        cfg.datasource_id = Some(datasource_id.to_owned());
        let c = caliban_connect::mongo::MongoConnector::connect(cfg).await.map_err(|e| e.to_string())?;
        c.verify_read_only().await.map_err(|e| e.to_string())?;
        c.introspect_with(&caliban_connect::mongo::SampleConfig::default()).await.map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Job {
    pub id: String,
    pub datasource_id: String,
    pub tenant_id: String,
    /// `running`, `succeeded` or `failed`.
    pub status: &'static str,
    /// Collections (objects) the snapshot found.
    pub objects: usize,
    /// Elements written as proposals.
    pub proposed: usize,
    /// Proposals skipped: already reviewed by a human, or unchanged.
    pub skipped: usize,
    /// The ontology version the proposals were written in (`None`: nothing new).
    pub version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,
}

/// The jobs this control plane ran (newest last).
#[derive(Default)]
pub struct Jobs(parking_lot::Mutex<VecDeque<Job>>);

impl Jobs {
    pub fn put(&self, j: Job) {
        let mut q = self.0.lock();
        if let Some(x) = q.iter_mut().find(|x| x.id == j.id) {
            *x = j;
            return;
        }
        q.push_back(j);
        while q.len() > KEEP_JOBS {
            q.pop_front();
        }
    }

    /// The newest job of a datasource.
    pub fn latest(&self, datasource_id: &str) -> Option<Job> {
        self.0.lock().iter().rev().find(|j| j.datasource_id == datasource_id).cloned()
    }

    pub fn running(&self, datasource_id: &str) -> bool {
        self.0.lock().iter().any(|j| j.datasource_id == datasource_id && j.status == "running")
    }
}

/// Which proposals to write: not ones whose element a human already reviewed, not ones identical
/// to the pending proposal. Returns `(to write, skipped)`.
pub fn select(st: &State, tenant: &str, proposals: Vec<Element>) -> (Vec<Element>, usize) {
    let current = st.ontologies.get(tenant);
    let mut out = Vec::new();
    let mut skipped = 0;
    for p in proposals {
        match current.and_then(|o| o.elements.iter().find(|e| e.id == p.id)) {
            Some(e) if e.status != Status::Proposed => skipped += 1,
            Some(e) if e.same_proposal(&p) => skipped += 1,
            _ => out.push(p),
        }
    }
    (out, skipped)
}

/// `connection` with `{"env": ...}` and `{"file": ...}` references resolved (sealed values must be
/// opened before).
pub fn resolve_references(v: &Value) -> Result<Value, String> {
    match v {
        Value::Object(m) if m.len() == 1 && (m.contains_key("env") || m.contains_key("file")) => {
            let r: caliban_config::SecretRef = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
            let s = r.resolve().map_err(|e| e.to_string())?;
            Ok(Value::String(s.expose().to_owned()))
        }
        Value::Object(m) => m
            .iter()
            .map(|(k, x)| Ok((k.clone(), resolve_references(x)?)))
            .collect::<Result<_, String>>()
            .map(Value::Object),
        Value::Array(a) => a.iter().map(resolve_references).collect::<Result<_, _>>().map(Value::Array),
        _ => Ok(v.clone()),
    }
}

/// Runs one introspection job to its end (status, proposals, the datasource's status).
pub async fn run(cp: Arc<crate::ControlPlane>, mut job: Job, connection: Value, kind: String) {
    let introspector = cp.introspector();
    let snapshot =
        tokio::time::timeout(JOB_TIMEOUT, introspector.snapshot(&kind, &job.datasource_id, connection)).await;
    let result: Result<(), String> = match snapshot {
        Err(_) => Err(format!("introspection took longer than {} s", JOB_TIMEOUT.as_secs())),
        Ok(Err(e)) => Err(e),
        Ok(Ok(snap)) => {
            job.objects = snap.objects.len();
            let proposals = caliban_connect::bootstrap::propose(&snap);
            let (write, skipped) = select(&cp.store.state(), &job.tenant_id, proposals);
            job.skipped = skipped;
            if write.is_empty() {
                Ok(())
            } else {
                job.proposed = write.len();
                let m = Mutation::ProposeOntology { tenant_id: job.tenant_id.clone(), elements: write };
                match cp.store.apply(&format!("introspection:{}", job.id), m).await {
                    Ok(st) => {
                        job.version = st.ontologies.get(&job.tenant_id).map(|o| o.version);
                        Ok(())
                    }
                    Err(e) => Err(format!("writing the proposals: {e}")),
                }
            }
        }
    };
    let ds_status = match &result {
        Ok(()) => "ready",
        Err(e) => {
            tracing::warn!(datasource = %job.datasource_id, tenant = %job.tenant_id, error = %e, "introspection failed");
            "failed"
        }
    };
    job.status = if result.is_ok() { "succeeded" } else { "failed" };
    job.error = result.err();
    job.finished_at = Some(Utc::now());
    let m = Mutation::SetDatasourceStatus { id: job.datasource_id.clone(), status: ds_status.into() };
    if let Err(e) = cp.store.apply("introspection", m).await {
        tracing::warn!(datasource = %job.datasource_id, error = %e, "recording the datasource's status failed");
    }
    cp.introspections.put(job);
}
