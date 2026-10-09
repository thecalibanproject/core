//! In-process idempotency records (one router).

use super::{Begin, IdempotencyError, IdempotencyStore, LEASE_TTL, Lease, REPLAY_TTL, Record, StoredResponse};
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Default memory budget for stored responses.
pub const DEFAULT_MAX_BYTES: usize = 256 * 1024 * 1024;
/// Expired records are swept at most this often.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

struct Entry {
    record: Record,
    expires: Instant,
    bytes: usize,
}

struct State {
    entries: HashMap<String, Entry>,
    bytes: usize,
    last_sweep: Instant,
}

/// Records in a map, with expiry and a memory budget: past `max_bytes`, the completed records
/// closest to expiry are dropped first (their keys then run again on a retry). Pending records
/// are never evicted.
pub struct MemoryIdempotency {
    state: Mutex<State>,
    lease_ttl: Duration,
    replay_ttl: Duration,
    max_bytes: usize,
}

impl Default for MemoryIdempotency {
    fn default() -> Self {
        Self::new(LEASE_TTL, REPLAY_TTL, DEFAULT_MAX_BYTES)
    }
}

impl MemoryIdempotency {
    pub fn new(lease_ttl: Duration, replay_ttl: Duration, max_bytes: usize) -> Self {
        Self {
            state: Mutex::new(State { entries: HashMap::new(), bytes: 0, last_sweep: Instant::now() }),
            lease_ttl,
            replay_ttl,
            max_bytes,
        }
    }

    /// Records held (tests and diagnostics).
    pub fn len(&self) -> usize {
        self.state.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn begin_sync(&self, tenant: &str, key: &str, fingerprint: &str) -> Begin {
        let now = Instant::now();
        let mut st = self.state.lock();
        sweep(&mut st, now, false);
        let id = super::record_id(tenant, key);
        if let Some(e) = st.entries.get(&id).filter(|e| e.expires > now) {
            return super::judge(&e.record, fingerprint);
        }
        let lease = super::new_lease(tenant, key, fingerprint);
        put(&mut st, id, lease.pending(), now + self.lease_ttl);
        Begin::Started(lease)
    }

    fn complete_sync(&self, lease: &Lease, response: Option<StoredResponse>) {
        let now = Instant::now();
        let mut st = self.state.lock();
        if !holds(&st, lease, now) {
            return;
        }
        put(&mut st, lease.id.clone(), super::done(lease, response), now + self.replay_ttl);
        if st.bytes > self.max_bytes {
            sweep(&mut st, now, true);
            evict(&mut st, self.max_bytes);
        }
    }

    fn release_sync(&self, lease: &Lease) {
        let mut st = self.state.lock();
        if holds(&st, lease, Instant::now())
            && let Some(e) = st.entries.remove(&lease.id)
        {
            st.bytes -= e.bytes;
        }
    }
}

/// The record under `lease.id` is still this lease's pending claim.
fn holds(st: &State, lease: &Lease, now: Instant) -> bool {
    st.entries
        .get(&lease.id)
        .is_some_and(|e| e.expires > now && matches!(&e.record, Record::Pending { token, .. } if *token == lease.token))
}

fn size(r: &Record) -> usize {
    match r {
        Record::Pending { .. } => 128,
        Record::Done { response, .. } => {
            128 + response
                .as_ref()
                .map_or(0, |r| r.body.len() + r.headers.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>())
        }
    }
}

fn put(st: &mut State, id: String, record: Record, expires: Instant) {
    let bytes = size(&record);
    if let Some(old) = st.entries.insert(id, Entry { record, expires, bytes }) {
        st.bytes -= old.bytes;
    }
    st.bytes += bytes;
}

fn sweep(st: &mut State, now: Instant, force: bool) {
    if !force && now.duration_since(st.last_sweep) < SWEEP_EVERY {
        return;
    }
    st.last_sweep = now;
    let mut freed = 0;
    st.entries.retain(|_, e| {
        let keep = e.expires > now;
        if !keep {
            freed += e.bytes;
        }
        keep
    });
    st.bytes -= freed;
}

fn evict(st: &mut State, max_bytes: usize) {
    let mut done: Vec<(Instant, String)> = st
        .entries
        .iter()
        .filter(|(_, e)| matches!(e.record, Record::Done { .. }))
        .map(|(k, e)| (e.expires, k.clone()))
        .collect();
    done.sort_unstable();
    for (_, k) in done {
        if st.bytes <= max_bytes {
            break;
        }
        if let Some(e) = st.entries.remove(&k) {
            st.bytes -= e.bytes;
        }
    }
}

#[async_trait]
impl IdempotencyStore for MemoryIdempotency {
    async fn begin(&self, tenant: &str, key: &str, fingerprint: &str) -> Result<Begin, IdempotencyError> {
        Ok(self.begin_sync(tenant, key, fingerprint))
    }

    async fn complete(&self, lease: &Lease, response: Option<StoredResponse>) {
        self.complete_sync(lease, response);
    }

    async fn release(&self, lease: &Lease) {
        self.release_sync(lease);
    }

    fn kind(&self) -> &'static str {
        "memory"
    }
}
