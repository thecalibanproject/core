//! `Idempotency-Key` records: the first request with a key runs, a duplicate while it runs is
//! refused, and a duplicate after it completed gets the stored response back.
//!
//! A record is scoped by tenant and key and holds the request fingerprint (method, path and body
//! hash), so the same key with another body is told apart. States:
//!
//! - **pending**: claimed by a running request, with a random lease token; expires after
//!   [`LEASE_TTL`] so a router that dies mid-request does not block the key for good.
//! - **done**: the response (status, headers, body) for [`REPLAY_TTL`], or a marker that the
//!   request completed but its response was too large to keep ([`MAX_STORED_BYTES`]).
//!
//! Only the lease holder can complete or release a pending record (compare the token), so a
//! request whose lease expired cannot overwrite a newer claim.
//!
//! Stores ([`IdempotencyStore`]):
//! - [`MemoryIdempotency`]: one router process (the default).
//! - [`ValkeyIdempotency`]: shared by every router; claim, complete and release are one Lua script
//!   each (atomic on the server). Keys are `<prefix>:idem:{<hash>}`, where the hash covers tenant
//!   and key, so client-chosen keys never reach Valkey verbatim.
//! - [`FallbackIdempotency`]: Valkey, with this router's memory store while Valkey is unreachable.
//!   During an outage a key is only deduplicated on the router that saw it.

mod memory;
mod valkey;

pub use memory::MemoryIdempotency;
pub use valkey::{FallbackIdempotency, ValkeyIdempotency};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// How long a completed request's response is replayed.
pub const REPLAY_TTL: Duration = Duration::from_secs(24 * 3600);
/// How long a running request holds its key before another request may claim it.
pub const LEASE_TTL: Duration = Duration::from_secs(15 * 60);
/// Largest response body kept for replay. A larger response completes the key without a body: a
/// duplicate then gets a conflict instead of a second run.
pub const MAX_STORED_BYTES: usize = 4 * 1024 * 1024;

/// A response to replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum Record {
    Pending {
        fp: String,
        token: String,
    },
    Done {
        fp: String,
        /// `None`: completed, response not kept.
        response: Option<StoredResponse>,
    },
}

/// What [`IdempotencyStore::begin`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Begin {
    /// The key is ours: run the request, then complete or release it.
    Started(Lease),
    /// Another request with this key is running.
    InProgress,
    /// The key was used for a different request (method, path or body).
    Mismatch,
    /// The request completed: its response (`None` when it was too large to keep).
    Replay(Option<StoredResponse>),
}

/// A claim on a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// Store key (hash of tenant and client key).
    pub(crate) id: String,
    pub(crate) fp: String,
    pub(crate) token: String,
    /// Claimed in the fallback's local store.
    pub(crate) local: bool,
}

impl Lease {
    fn pending(&self) -> Record {
        Record::Pending { fp: self.fp.clone(), token: self.token.clone() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("idempotency store unavailable: {0}")]
pub struct IdempotencyError(pub String);

#[async_trait]
pub trait IdempotencyStore: Send + Sync {
    /// Claims `key` for `tenant`, or reports what holds it. `fingerprint` identifies the request.
    async fn begin(&self, tenant: &str, key: &str, fingerprint: &str) -> Result<Begin, IdempotencyError>;

    /// Stores the result of a claimed request (`None`: completed, not replayable).
    async fn complete(&self, lease: &Lease, response: Option<StoredResponse>);

    /// Frees the key so a retry runs again (the request failed or was abandoned).
    async fn release(&self, lease: &Lease);

    /// `memory` or `valkey`.
    fn kind(&self) -> &'static str;
}

/// Store id of a tenant's key: neither the tenant id nor the client's key is used verbatim.
pub(crate) fn record_id(tenant: &str, key: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"caliban/idempotency/v1\0");
    h.update(&(tenant.len() as u64).to_le_bytes());
    h.update(tenant.as_bytes());
    h.update(key.as_bytes());
    h.finalize().to_hex().to_string()
}

fn new_lease(tenant: &str, key: &str, fingerprint: &str) -> Lease {
    Lease {
        id: record_id(tenant, key),
        fp: fingerprint.to_owned(),
        token: uuid::Uuid::new_v4().to_string(),
        local: false,
    }
}

/// What a duplicate gets, given the record that holds its key.
fn judge(existing: &Record, fingerprint: &str) -> Begin {
    match existing {
        Record::Pending { fp, .. } | Record::Done { fp, .. } if fp != fingerprint => Begin::Mismatch,
        Record::Pending { .. } => Begin::InProgress,
        Record::Done { response, .. } => Begin::Replay(response.clone()),
    }
}

/// A completed record for `lease` (the body is dropped when over [`MAX_STORED_BYTES`]).
fn done(lease: &Lease, response: Option<StoredResponse>) -> Record {
    Record::Done { fp: lease.fp.clone(), response: response.filter(|r| r.body.len() <= MAX_STORED_BYTES) }
}

#[cfg(test)]
mod store_tests;
