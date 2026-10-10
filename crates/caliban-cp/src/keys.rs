//! Tenant data keys on the control plane (envelope encryption).
//!
//! Key hierarchy (primitives in `caliban_config`, AES-256-GCM from the `aes-gcm` crate):
//! - KEK keyring: `CALIBAN_KEK` (current) and `CALIBAN_KEK_PREVIOUS` (retired, used to open only).
//! - One DEK per tenant, created on the tenant's first secret and stored wrapped by the current
//!   KEK (associated data: tenant id and KEK id) in `tenant_dek` ([`State::deks`]).
//! - The tenant's secrets, sealed under its DEK (associated data: tenant id): BYOK provider keys
//!   ([`StoredSecret::TenantDek`]) and datasource credentials (`{"$sealed": ...}` objects inside
//!   `connection`).
//!
//! Deleting a tenant deletes its DEK in the same transaction (crypto-shredding). A database backup
//! taken earlier still holds the wrapped DEK, which stays openable for as long as the KEK that
//! wrapped it exists. `caliban keys rotate` re-wraps every live DEK (and re-seals shared provider
//! keys) under the current KEK, after which the old KEK can be destroyed and old backups no longer
//! open for any tenant.
//!
//! Routers receive BYOK keys as self-contained envelopes in the signed snapshot (wrapped DEK +
//! ciphertext, see `caliban_config::TenantSealed`) and open them per request with their own
//! keyring: the same trust model as before (routers hold the KEK; keys are never sent in clear).

use crate::store::audit::now_micros;
use crate::store::{
    ConnectionChange, DekChange, DekRecord, Mutation, ProviderSecretChange, Rekey, SharedSecretChange, State, Store,
    StoreError, StoredSecret,
};
use caliban_config::{Dek, Keyring, SecretRef};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Marker key of a sealed value inside a datasource `connection`.
pub const SEALED: &str = "$sealed";
/// Optional display form stored next to a sealed URI (credentials masked).
pub const REDACTED: &str = "$redacted";
/// What a secret looks like in API responses.
pub const MASK: &str = "****";

/// A new DEK for `tenant`, wrapped by the current KEK.
pub fn new_dek(keyring: &Keyring, tenant: &str) -> (Dek, DekRecord) {
    let dek = Dek::generate();
    let rec = DekRecord { wrapped: keyring.wrap_dek(tenant, &dek), created_at: now_micros() };
    (dek, rec)
}

/// The tenant's DEK, created (one `tenant_key.create` audit row) on first use.
pub async fn tenant_dek(store: &Store, keyring: &Keyring, tenant: &str, actor: &str) -> Result<Dek, StoreError> {
    for _ in 0..3 {
        // Another control-plane replica may have created it.
        store.refresh().await?;
        if let Some(d) = store.state().deks.get(tenant) {
            return keyring
                .unwrap_dek(tenant, &d.wrapped)
                .map_err(|e| StoreError::Backend(format!("cannot open the data key of tenant {tenant}: {e}")));
        }
        let (dek, rec) = new_dek(keyring, tenant);
        match store.apply(actor, Mutation::CreateDek { tenant_id: tenant.into(), dek: rec }).await {
            Ok(_) => return Ok(dek),
            // Created concurrently: use that one.
            Err(StoreError::Conflict(_)) => {}
            Err(e) => return Err(e),
        }
    }
    Err(StoreError::Conflict("the tenant's data key is being created concurrently; retry".into()))
}

// ───────────────────────────── datasource connections ─────────────────────────────

fn normalized(name: &str) -> String {
    name.chars().filter(char::is_ascii_alphanumeric).map(|c| c.to_ascii_lowercase()).collect()
}

/// Field names whose values are credentials (`password`, `api_key`, `client_secret`,
/// `access_token`, `private_key`, `credentials`, `connection_string`, ...). Names that only point
/// at one (`token_url`, `password_file`, `secret_name`, ...) are not.
pub fn is_secret_field(name: &str) -> bool {
    const POINTERS: &[&str] = &["url", "uri", "endpoint", "type", "path", "file", "env", "name"];
    const EXACT: &[&str] = &["pass", "pwd"];
    const PARTS: &[&str] = &[
        "password",
        "passwd",
        "passphrase",
        "secret",
        "token",
        "apikey",
        "privatekey",
        "credential",
        "connectionstring",
        "authorization",
    ];
    let n = normalized(name);
    if POINTERS.iter().any(|p| n.ends_with(p)) {
        return false;
    }
    EXACT.contains(&n.as_str()) || PARTS.iter().any(|p| n.contains(p))
}

/// `{"env": "NAME"}` or `{"file": "/path"}`: a reference, not a secret.
fn is_reference(v: &Value) -> bool {
    matches!(v, Value::Object(m) if m.len() == 1 && m.iter().all(|(k, v)| (k == "env" || k == "file") && v.is_string()))
}

fn is_sealed(v: &Value) -> bool {
    matches!(v, Value::Object(m) if m.get(SEALED).is_some_and(Value::is_string))
}

fn non_empty(v: &Value) -> bool {
    match v {
        Value::String(s) => !s.is_empty(),
        Value::Object(m) => !m.is_empty(),
        Value::Array(a) => !a.is_empty(),
        _ => false,
    }
}

/// Masks `k=v` pairs whose key is a secret field. Returns `None` if nothing was masked.
fn mask_pairs(s: &str, sep: char) -> Option<String> {
    let mut changed = false;
    let parts: Vec<String> = s
        .split(sep)
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) if !v.is_empty() && is_secret_field(k.trim()) => {
                changed = true;
                format!("{k}={MASK}")
            }
            _ => pair.to_owned(),
        })
        .collect();
    changed.then(|| parts.join(&sep.to_string()))
}

/// `s` with its credentials masked, if it carries any: a URI password (`scheme://user:pw@host`),
/// secret query parameters (`?password=...`, `&token=...`) or secret `key=value;` pairs
/// (`Server=h;Password=...`). `None` when `s` carries none.
pub fn redact_str(s: &str) -> Option<String> {
    let mut out = s.to_owned();
    let mut changed = false;
    if let Some(i) = out.find("://") {
        let start = i + 3;
        // The userinfo ends at the last '@' before the query: passwords with an unescaped '/' or
        // '@' are still caught (at worst a path with '@' is masked too).
        let end = out[start..].find(['?', '#']).map_or(out.len(), |e| start + e);
        if let Some(at) = out[start..end].rfind('@').map(|a| start + a)
            && let Some(colon) = out[start..at].find(':').map(|c| start + c)
        {
            out = format!("{}{MASK}{}", &out[..=colon], &out[at..]);
            changed = true;
        }
    }
    if let Some(q) = out.find('?') {
        let (head, query) = out.split_at(q + 1);
        let (query, frag) = query.split_once('#').map_or((query, None), |(a, b)| (a, Some(b)));
        if let Some(masked) = mask_pairs(query, '&') {
            out = format!("{head}{masked}{}", frag.map(|f| format!("#{f}")).unwrap_or_default());
            changed = true;
        }
    }
    if out.contains(';')
        && out.contains('=')
        && let Some(masked) = mask_pairs(&out, ';')
    {
        out = masked;
        changed = true;
    }
    changed.then_some(out)
}

/// Walks `v`, calling `f(value, redacted_form)` on every value that must be sealed (secret field,
/// or a string carrying credentials) and replacing it with the result. References and values
/// already sealed are left alone.
fn walk(v: &Value, key: Option<&str>, f: &mut dyn FnMut(&Value, Option<String>) -> Value) -> Value {
    if is_reference(v) || is_sealed(v) {
        return v.clone();
    }
    if key.is_some_and(is_secret_field) && non_empty(v) {
        return f(v, None);
    }
    match v {
        Value::String(s) => match redact_str(s) {
            Some(r) => f(v, Some(r)),
            None => v.clone(),
        },
        Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), walk(x, Some(k), f))).collect()),
        Value::Array(a) => Value::Array(a.iter().map(|x| walk(x, None, f)).collect()),
        _ => v.clone(),
    }
}

/// True if `conn` has credentials in clear.
pub fn needs_sealing(conn: &Value) -> bool {
    let mut n = 0;
    walk(conn, None, &mut |v, _| {
        n += 1;
        v.clone()
    });
    n > 0
}

/// Seals every credential in `conn` under the tenant DEK: `{"$sealed": "<base64>"}`, plus
/// `"$redacted"` (the masked string) for URIs and connection strings.
pub fn seal_connection(conn: &Value, tenant: &str, dek: &Dek) -> Value {
    walk(conn, None, &mut |v, redacted| {
        let plaintext = Zeroizing::new(v.to_string());
        let mut m = Map::new();
        m.insert(SEALED.into(), Value::String(dek.seal(tenant, &plaintext)));
        if let Some(r) = redacted {
            m.insert(REDACTED.into(), Value::String(r));
        }
        Value::Object(m)
    })
}

/// The connection with its sealed values opened (for the connectors; never for API responses).
pub fn open_connection(conn: &Value, tenant: &str, dek: &Dek) -> Result<Value, String> {
    match conn {
        Value::Object(m) if is_sealed(conn) => {
            let ct = m.get(SEALED).and_then(Value::as_str).unwrap_or_default();
            let plaintext = Zeroizing::new(dek.open(tenant, ct)?);
            serde_json::from_str(&plaintext).map_err(|e| e.to_string())
        }
        Value::Object(m) => m
            .iter()
            .map(|(k, v)| Ok((k.clone(), open_connection(v, tenant, dek)?)))
            .collect::<Result<_, _>>()
            .map(Value::Object),
        Value::Array(a) => {
            a.iter().map(|v| open_connection(v, tenant, dek)).collect::<Result<_, _>>().map(Value::Array)
        }
        _ => Ok(conn.clone()),
    }
}

/// What the API shows: sealed values as their masked form (or `****`), and any credential still
/// in clear masked as well.
pub fn redact_connection(conn: &Value) -> Value {
    fn go(v: &Value, key: Option<&str>) -> Value {
        if is_sealed(v) {
            return v.get(REDACTED).cloned().unwrap_or_else(|| Value::String(MASK.into()));
        }
        if is_reference(v) {
            return v.clone();
        }
        if key.is_some_and(is_secret_field) && non_empty(v) {
            return Value::String(MASK.into());
        }
        match v {
            Value::String(s) => redact_str(s).map_or_else(|| v.clone(), Value::String),
            Value::Object(m) => Value::Object(m.iter().map(|(k, x)| (k.clone(), go(x, Some(k)))).collect()),
            Value::Array(a) => Value::Array(a.iter().map(|x| go(x, None)).collect()),
            _ => v.clone(),
        }
    }
    go(conn, None)
}

pub fn serialize_redacted<S: serde::Serializer>(conn: &Value, s: S) -> Result<S::Ok, S::Error> {
    redact_connection(conn).serialize(s)
}

/// Number of sealed values in `conn`.
pub fn count_sealed(conn: &Value) -> usize {
    match conn {
        v if is_sealed(v) => 1,
        Value::Object(m) => m.values().map(count_sealed).sum(),
        Value::Array(a) => a.iter().map(count_sealed).sum(),
        _ => 0,
    }
}

/// Clients cannot send pre-sealed values (`$sealed`, `$redacted` keys are reserved).
pub fn reject_reserved(conn: &Value) -> Result<(), String> {
    match conn {
        Value::Object(m) => {
            if m.contains_key(SEALED) || m.contains_key(REDACTED) {
                return Err(format!("'{SEALED}' and '{REDACTED}' are reserved in a datasource connection"));
            }
            m.values().try_for_each(reject_reserved)
        }
        Value::Array(a) => a.iter().try_for_each(reject_reserved),
        _ => Ok(()),
    }
}

// ───────────────────────────── migration and rotation ─────────────────────────────

/// Plans a [`Rekey`] from the committed state.
///
/// Always (startup migration, idempotent): every active tenant with BYOK keys still sealed
/// directly under a KEK, or with datasource credentials in clear, gets a DEK if it has none, and
/// those secrets are sealed under it. With `rotate`: every DEK not wrapped by the current KEK is
/// re-wrapped (same DEK), and shared provider keys not sealed under the current KEK are re-sealed.
///
/// Returns the plan and the problems that kept some items out of it (for example a DEK wrapped by
/// a KEK that is not in the keyring).
pub fn plan(st: &State, keyring: &Keyring, rotate: bool) -> (Rekey, Vec<String>) {
    let mut r = Rekey { rotate, kek_id: keyring.current_id().to_owned(), ..Rekey::default() };
    let mut problems = Vec::new();
    for t in st.tenants.iter().filter(|t| t.is_active()) {
        let legacy: Vec<_> = st
            .provider_keys
            .iter()
            .filter(|p| p.tenant_id == t.id && matches!(p.secret, Some(StoredSecret::Ref(SecretRef::Sealed { .. }))))
            .collect();
        let cleartext: Vec<_> = st
            .datasources
            .iter()
            .filter(|d| d.tenant_id == t.id && d.is_live() && needs_sealing(&d.connection))
            .collect();
        let existing = st.deks.get(&t.id);
        let rewrap = rotate && existing.is_some_and(|d| d.wrapped.kek_id != keyring.current_id());
        if legacy.is_empty() && cleartext.is_empty() && !rewrap {
            continue;
        }
        let dek = match existing {
            Some(d) => match keyring.unwrap_dek(&t.id, &d.wrapped) {
                Ok(k) => k,
                Err(e) => {
                    problems.push(format!("tenant {}: {e}", t.id));
                    continue;
                }
            },
            None => {
                let (k, rec) = new_dek(keyring, &t.id);
                r.deks.push(DekChange { tenant_id: t.id.clone(), prev: None, next: rec });
                k
            }
        };
        if let Some(d) = existing.filter(|_| rewrap) {
            r.deks.push(DekChange {
                tenant_id: t.id.clone(),
                prev: Some(d.wrapped.clone()),
                next: DekRecord { wrapped: keyring.wrap_dek(&t.id, &dek), created_at: d.created_at },
            });
        }
        for p in legacy {
            let Some(prev @ StoredSecret::Ref(SecretRef::Sealed { sealed })) = &p.secret else { continue };
            match keyring.open(sealed) {
                Ok(pt) => {
                    let pt = Zeroizing::new(pt);
                    r.provider_secrets.push(ProviderSecretChange {
                        tenant_id: t.id.clone(),
                        id: p.id.clone(),
                        prev: prev.clone(),
                        next: StoredSecret::TenantDek(dek.seal(&t.id, &pt)),
                    });
                }
                Err(e) => problems.push(format!("tenant {} provider key '{}': {e}", t.id, p.id)),
            }
        }
        for d in cleartext {
            r.datasources.push(ConnectionChange {
                tenant_id: t.id.clone(),
                id: d.id.clone(),
                prev: d.connection.clone(),
                next: seal_connection(&d.connection, &t.id, &dek),
            });
        }
    }
    if rotate {
        for sp in &st.shared_providers {
            let Some(prev @ SecretRef::Sealed { sealed }) = &sp.provider.api_key else { continue };
            if keyring.opens_with_current(sealed) {
                continue;
            }
            match keyring.open(sealed) {
                Ok(pt) => {
                    let pt = Zeroizing::new(pt);
                    r.shared_secrets.push(SharedSecretChange {
                        id: sp.provider.id.to_string(),
                        prev: prev.clone(),
                        next: SecretRef::Sealed { sealed: keyring.seal(&pt) },
                    });
                }
                Err(e) => problems.push(format!("shared provider '{}': {e}", sp.provider.id)),
            }
        }
    }
    (r, problems)
}

/// What `caliban keys status` prints: which KEK wraps what, what is still waiting for migration,
/// and whether the retired KEKs (`CALIBAN_KEK_PREVIOUS`) are still needed by the live database.
pub fn status(st: &State, keyring: Option<&Keyring>) -> Value {
    let mut deks_by_kek: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (tenant, d) in &st.deks {
        deks_by_kek.entry(d.wrapped.kek_id.as_str()).or_default().push(tenant);
    }
    let mut shared_by_kek: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for sp in &st.shared_providers {
        if let Some(SecretRef::Sealed { sealed }) = &sp.provider.api_key {
            let id = keyring.and_then(|k| k.opener_id(sealed)).unwrap_or("unknown (not in this keyring)");
            shared_by_kek.entry(id.to_owned()).or_default().push(sp.provider.id.to_string());
        }
    }
    let legacy: Vec<String> = st
        .provider_keys
        .iter()
        .filter(|p| matches!(p.secret, Some(StoredSecret::Ref(SecretRef::Sealed { .. }))))
        .map(|p| format!("{}/{}", p.tenant_id, p.id))
        .collect();
    let cleartext: Vec<&str> =
        st.datasources.iter().filter(|d| d.is_live() && needs_sealing(&d.connection)).map(|d| d.id.as_str()).collect();
    let mut out = json!({
        "tenant_keys_by_kek": deks_by_kek,
        "shared_provider_keys_by_kek": shared_by_kek,
        "provider_keys_sealed_directly_under_a_kek": legacy,
        "datasources_with_credentials_in_clear": cleartext,
    });
    if let Some(k) = keyring {
        let previous: Vec<&str> = k.ids().into_iter().skip(1).collect();
        let in_use = |id: &str| deks_by_kek.contains_key(id) || shared_by_kek.contains_key(id);
        let still_needed: Vec<&str> = previous.iter().copied().filter(|id| in_use(id)).collect();
        out["keyring"] = json!({"current": k.current_id(), "previous": previous});
        out["previous_keks_still_needed"] = json!(still_needed);
        out["rotation_complete"] = json!(still_needed.is_empty() && legacy.is_empty());
    }
    out
}

/// Adds what split-mode routers reported on their snapshot polls to a [`status`] report:
///
/// - `routers`: every router that checked in, with `active` (seen within
///   [`crate::store::ROUTER_ACTIVE_SECS`]), the snapshot it serves and the KEKs that snapshot
///   needs (`snapshot_kek_ids`), its own keyring, `needs_previous_kek` (its snapshot still needs a
///   retired KEK of `keyring`) and `has_current_kek` (its keyring holds the current KEK).
/// - `routers_on_previous_keks`: active routers whose snapshot still needs a retired KEK. They
///   have not polled since `keys rotate`; removing `CALIBAN_KEK_PREVIOUS` from them now would
///   break their BYOK keys until they do.
/// - `routers_without_current_kek`: active routers that do not hold the current KEK yet (step 1 of
///   the rotation is not done on them).
/// - `rotation_complete` additionally requires `routers_on_previous_keks` to be empty.
///
/// Inactive routers are listed but do not hold up the rotation: when one comes back it polls
/// before serving.
pub fn add_routers(
    out: &mut Value,
    routers: &[crate::store::RouterStatus],
    keyring: Option<&Keyring>,
    now: chrono::DateTime<chrono::Utc>,
) {
    let previous: Vec<&str> = keyring.map(|k| k.ids().into_iter().skip(1).collect()).unwrap_or_default();
    let current = keyring.map(Keyring::current_id);
    let mut on_previous = Vec::new();
    let mut without_current = Vec::new();
    let list: Vec<Value> = routers
        .iter()
        .map(|r| {
            let active = (now - r.last_seen).num_seconds() <= crate::store::ROUTER_ACTIVE_SECS;
            let needs_previous = r.snapshot_kek_ids.iter().any(|id| previous.contains(&id.as_str()));
            let has_current = current.map(|c| r.keyring.iter().any(|id| id == c));
            if active && needs_previous {
                on_previous.push(r.router_id.clone());
            }
            if active && has_current == Some(false) {
                without_current.push(r.router_id.clone());
            }
            json!({
                "router_id": r.router_id,
                "last_seen": r.last_seen,
                "active": active,
                "snapshot_version": r.snapshot_version,
                "snapshot_kek_ids": r.snapshot_kek_ids,
                "keyring": r.keyring,
                "needs_previous_kek": needs_previous,
                "has_current_kek": has_current,
            })
        })
        .collect();
    out["routers"] = json!(list);
    if keyring.is_some() {
        out["routers_on_previous_keks"] = json!(on_previous);
        out["routers_without_current_kek"] = json!(without_current);
        if let Some(done) = out.get("rotation_complete").and_then(Value::as_bool) {
            out["rotation_complete"] = json!(done && on_previous.is_empty());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routers_hold_up_the_rotation_until_they_serve_the_new_snapshot() {
        use crate::store::RouterStatus;
        let ring = Keyring::new([2; 32], [[1; 32]]);
        let (new, old) = (ring.current_id().to_owned(), ring.ids()[1].to_owned());
        let now = chrono::Utc::now();
        let r = |id: &str, kek: &str, ago: i64| RouterStatus {
            router_id: id.into(),
            last_seen: now - chrono::Duration::seconds(ago),
            snapshot_version: "cp-49".into(),
            snapshot_kek_ids: vec![kek.into()],
            keyring: vec![new.clone(), old.clone()],
        };
        let base = || json!({"previous_keks_still_needed": [], "rotation_complete": true});
        let mut out = base();
        add_routers(&mut out, &[r("a", &new, 5), r("b", &old, 5), r("gone", &old, 3600)], Some(&ring), now);
        assert_eq!(out["routers_on_previous_keks"], json!(["b"]), "the inactive router does not count");
        assert_eq!(out["rotation_complete"], false);
        assert_eq!(out["routers"][2]["active"], false);
        assert_eq!(out["routers"][1]["needs_previous_kek"], true);

        // b polls the re-wrapped snapshot.
        let mut out = base();
        add_routers(&mut out, &[r("a", &new, 5), r("b", &new, 1)], Some(&ring), now);
        assert_eq!(
            (out["routers_on_previous_keks"].clone(), out["rotation_complete"].clone()),
            (json!([]), json!(true))
        );

        // A router without the new KEK in its keyring is reported.
        let mut lagging = r("c", &old, 1);
        lagging.keyring = vec![old.clone()];
        let mut out = base();
        add_routers(&mut out, &[lagging], Some(&ring), now);
        assert_eq!(out["routers_without_current_kek"], json!(["c"]));
    }

    #[test]
    fn secret_fields_and_pointers() {
        for f in ["password", "PASSWORD", "db_password", "passwd", "pwd", "pass", "api_key", "apiKey", "x-api-key"] {
            assert!(is_secret_field(f), "{f}");
        }
        for f in ["client_secret", "access_token", "private_key", "credentials", "connection_string", "token"] {
            assert!(is_secret_field(f), "{f}");
        }
        for f in ["user", "username", "host", "authSource", "token_url", "password_file", "secret_name", "database"] {
            assert!(!is_secret_field(f), "{f}");
        }
    }

    #[test]
    fn credentials_in_strings_are_masked() {
        assert_eq!(redact_str("mongodb://u:p@h/db").as_deref(), Some("mongodb://u:****@h/db"));
        assert_eq!(
            redact_str("mongodb+srv://u:p/w@d@h1,h2/db?x=1").as_deref(),
            Some("mongodb+srv://u:****@h1,h2/db?x=1")
        );
        assert_eq!(
            redact_str("postgres://h/db?user=u&password=x#f").as_deref(),
            Some("postgres://h/db?user=u&password=****#f")
        );
        assert_eq!(redact_str("Server=h;User Id=u;Password=x;").as_deref(), Some("Server=h;User Id=u;Password=****;"));
        assert_eq!(redact_str("mongodb://h:27017/db"), None);
        assert_eq!(redact_str("mongodb://u@h/db"), None);
        assert_eq!(redact_str("plain text"), None);
    }

    #[test]
    fn connections_are_sealed_redacted_and_opened() {
        let dek = Dek::generate();
        let conn = json!({
            "uri": "mongodb://app:hunter2@db:27017/sales",
            "auth": {"username": "app", "password": "hunter2"},
            "credentials": {"type": "service_account", "private_key": "-----BEGIN fake-----"},
            "api_key": {"env": "SALES_API_KEY"},
            "token_url": "https://idp/token",
            "hosts": ["h1:27017", "https://u:pw@h2"],
            "port": 27017,
            "password_blank": "",
        });
        assert!(needs_sealing(&conn));
        let sealed = seal_connection(&conn, "acme", &dek);
        assert!(!needs_sealing(&sealed), "{sealed}");
        assert_eq!(count_sealed(&sealed), 4);
        let text = sealed.to_string();
        assert!(!text.contains("hunter2") && !text.contains("BEGIN fake") && !text.contains(":pw@"), "{text}");
        assert_eq!(sealed["api_key"], json!({"env": "SALES_API_KEY"}), "references stay references");
        assert_eq!(sealed["token_url"], "https://idp/token");
        assert_eq!(sealed["auth"]["username"], "app");
        // Idempotent: sealing again changes nothing.
        assert_eq!(seal_connection(&sealed, "acme", &dek), sealed);
        // The API view.
        let view = redact_connection(&sealed);
        assert_eq!(view["uri"], "mongodb://app:****@db:27017/sales");
        assert_eq!(view["auth"]["password"], MASK);
        assert_eq!(view["credentials"], MASK);
        assert_eq!(view["hosts"], json!(["h1:27017", "https://u:****@h2"]));
        assert_eq!(redact_connection(&conn), view, "cleartext is redacted the same way");
        // Round trip with the right tenant only.
        assert_eq!(open_connection(&sealed, "acme", &dek).unwrap(), conn);
        assert!(open_connection(&sealed, "globex", &dek).is_err());
        assert!(reject_reserved(&json!({"a": [{"$sealed": "x"}]})).is_err());
        assert!(reject_reserved(&conn).is_ok());
    }
}
