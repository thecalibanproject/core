//! Tamper-evident audit log: every control-plane mutation appends one row, hash-chained.
//!
//! `hash = sha256(prev_hash ‖ canonical_json(row))` where `row` is
//! `{seq, ts, tenant_id, actor, action, target, detail}` serialized with sorted keys and no
//! whitespace, `ts` as RFC 3339 UTC with microseconds, and `prev_hash` is 32 zero bytes for the
//! first row (stored as NULL). Rewriting any row breaks every later hash; the Postgres table
//! additionally rejects UPDATE/DELETE with a trigger.

use chrono::{DateTime, SecondsFormat, Timelike, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// What a mutation wants recorded (the store adds seq, ts, actor and the hashes).
#[derive(Debug, Clone)]
pub struct AuditDraft {
    pub tenant_id: Option<String>,
    pub action: &'static str,
    pub target: Option<String>,
    /// Never secrets or raw prompt content. Keep to strings, integers and booleans so the
    /// canonical form survives a JSONB round trip unchanged.
    pub detail: Value,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AuditEntry {
    pub seq: u64,
    pub ts: DateTime<Utc>,
    pub tenant_id: Option<String>,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub detail: Value,
    /// Hex; `None` for the first row.
    pub prev_hash: Option<String>,
    pub hash: String,
}

/// Postgres stores microseconds; truncate so the hash recomputes after a round trip.
pub fn now_micros() -> DateTime<Utc> {
    let now = Utc::now();
    now.with_nanosecond(now.nanosecond() / 1_000 * 1_000).unwrap_or(now)
}

impl AuditEntry {
    /// Builds the next row after `prev` (None = genesis).
    pub fn next(prev: Option<&AuditEntry>, actor: &str, d: &AuditDraft, ts: DateTime<Utc>) -> Self {
        let mut e = AuditEntry {
            seq: prev.map_or(1, |p| p.seq + 1),
            ts,
            tenant_id: d.tenant_id.clone(),
            actor: actor.to_owned(),
            action: d.action.to_owned(),
            target: d.target.clone(),
            detail: d.detail.clone(),
            prev_hash: prev.map(|p| p.hash.clone()),
            hash: String::new(),
        };
        e.hash = hex::encode(e.compute_hash());
        e
    }

    pub fn canonical_row(&self) -> String {
        canonical_json(&json!({
            "seq": self.seq,
            "ts": self.ts.to_rfc3339_opts(SecondsFormat::Micros, true),
            "tenant_id": self.tenant_id,
            "actor": self.actor,
            "action": self.action,
            "target": self.target,
            "detail": self.detail,
        }))
    }

    pub fn compute_hash(&self) -> [u8; 32] {
        let prev = self.prev_hash.as_deref().and_then(|h| hex::decode(h).ok()).unwrap_or_else(|| vec![0u8; 32]);
        let mut h = Sha256::new();
        h.update(&prev);
        h.update(self.canonical_row().as_bytes());
        h.finalize().into()
    }
}

/// Checks a contiguous, ascending run of rows: each hash recomputes and links to the previous
/// row's hash. Returns the first bad `seq`.
pub fn verify_chain(entries: &[AuditEntry]) -> Result<(), u64> {
    for (i, e) in entries.iter().enumerate() {
        if hex::encode(e.compute_hash()) != e.hash {
            return Err(e.seq);
        }
        if let Some(prev) = i.checked_sub(1).map(|j| &entries[j]) {
            if e.seq != prev.seq + 1 || e.prev_hash.as_deref() != Some(prev.hash.as_str()) {
                return Err(e.seq);
            }
        } else if e.seq == 1 && e.prev_hash.is_some() {
            return Err(e.seq);
        }
    }
    Ok(())
}

/// Deterministic JSON: object keys sorted, no whitespace. Independent of serde_json's map
/// ordering features.
pub fn canonical_json(v: &Value) -> String {
    let mut out = String::new();
    write_canonical(v, &mut out);
    out
}

fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                write_canonical(&m[k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft(action: &'static str, n: u64) -> AuditDraft {
        AuditDraft {
            tenant_id: Some("acme".into()),
            action,
            target: Some(format!("t{n}")),
            detail: json!({"b": n, "a": "x"}),
        }
    }

    fn chain(n: u64) -> Vec<AuditEntry> {
        let mut v: Vec<AuditEntry> = Vec::new();
        for i in 0..n {
            let e = AuditEntry::next(v.last(), "admin", &draft("tenant.create", i), now_micros());
            v.push(e);
        }
        v
    }

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let v = json!({"b": 1, "a": {"d": [true, null], "c": "x\"y"}});
        assert_eq!(canonical_json(&v), r#"{"a":{"c":"x\"y","d":[true,null]},"b":1}"#);
    }

    #[test]
    fn chain_verifies_and_links() {
        let c = chain(5);
        assert_eq!(c[0].prev_hash, None);
        assert_eq!(c[3].prev_hash.as_deref(), Some(c[2].hash.as_str()));
        assert!(verify_chain(&c).is_ok());
        // Any window of the chain verifies on its own.
        assert!(verify_chain(&c[2..]).is_ok());
    }

    #[test]
    fn tampering_is_detected() {
        let mut c = chain(4);
        c[1].detail = json!({"a": "x", "b": 999});
        assert_eq!(verify_chain(&c), Err(2));

        // Recomputing the edited row's hash still breaks the link from the next row.
        let mut c = chain(4);
        c[1].actor = "mallory".into();
        c[1].hash = hex::encode(c[1].compute_hash());
        assert_eq!(verify_chain(&c), Err(3));

        // Deleting a row breaks the sequence/link.
        let mut c = chain(4);
        c.remove(2);
        assert_eq!(verify_chain(&c), Err(4));
    }
}
