//! Read-only verification from `connectionStatus { showPrivileges: true }` (research 08, "Safety").
//!
//! Caliban requires a dedicated user with a custom role (`find`, `listCollections`, `listIndexes`,
//! `collStats`, `dbStats`, plus `changeStream` for CDC). Classification is fail-closed: any action
//! that is not on the read/monitoring allow-list refuses the connection, and known write/admin
//! actions are reported by name.

use serde::{Deserialize, Serialize};
use serde_json::Value as J;
use std::collections::BTreeSet;

/// Actions granted by `read`, `readAnyDatabase` and `clusterMonitor`-style roles. None of them
/// changes data, schema, users or server state.
const READ_ACTIONS: &[&str] = &[
    "find",
    "listCollections",
    "listIndexes",
    "listSearchIndexes",
    "collStats",
    "dbStats",
    "dbHash",
    "changeStream",
    "killCursors",
    "planCacheRead",
    "indexStats",
    "listDatabases",
    "listShards",
    "listSessions",
    "connPoolStats",
    "getCmdLineOpts",
    "getDefaultRWConcern",
    "getLog",
    "getParameter",
    "getClusterParameter",
    "getShardMap",
    "getShardVersion",
    "hostInfo",
    "inprog",
    "netstat",
    "replSetGetConfig",
    "replSetGetStatus",
    "serverStatus",
    "shardingState",
    "top",
    "checkFreeMonitoringStatus",
    "checkMetadataConsistency",
    "operationMetrics",
    "queryStatsRead",
    "useUUID",
    "viewRole",
    "viewUser",
    // MongoDB 8.x adds this to the built-in `read` role: raw access to time-series buckets.
    // Writing still requires insert/update/remove.
    "performRawDataOperations",
];

/// Well-known actions that write data, change schema/indexes, manage users/roles or administer
/// the server. Listed so the refusal names them; anything unknown is refused too.
const WRITE_ADMIN_ACTIONS: &[&str] = &[
    "anyAction",
    "internal",
    "insert",
    "update",
    "remove",
    "bypassDocumentValidation",
    "createCollection",
    "dropCollection",
    "renameCollection",
    "renameCollectionSameDB",
    "convertToCapped",
    "collMod",
    "compact",
    "compactStructuredEncryptionData",
    "createIndex",
    "dropIndex",
    "reIndex",
    "createSearchIndexes",
    "dropSearchIndex",
    "updateSearchIndex",
    "dropDatabase",
    "emptycapped",
    "enableProfiler",
    "planCacheWrite",
    "planCacheIndexFilter",
    "createUser",
    "dropUser",
    "updateUser",
    "grantRole",
    "revokeRole",
    "createRole",
    "dropRole",
    "grantRolesToUser",
    "revokeRolesFromUser",
    "changePassword",
    "changeOwnPassword",
    "changeCustomData",
    "changeOwnCustomData",
    "setAuthenticationRestriction",
    "invalidateUserCache",
    "impersonate",
    "shutdown",
    "fsync",
    "applyOps",
    "setParameter",
    "setClusterParameter",
    "setFeatureCompatibilityVersion",
    "setDefaultRWConcern",
    "setUserWriteBlockMode",
    "bypassWriteBlockingMode",
    "replSetConfigure",
    "replSetStateChange",
    "resync",
    "addShard",
    "removeShard",
    "enableSharding",
    "moveChunk",
    "splitChunk",
    "refineCollectionShardKey",
    "reshardCollection",
    "cleanupOrphaned",
    "killop",
    "killAnySession",
    "killAnyCursor",
    "dropConnections",
    "logRotate",
    "restore",
    "appendOplogNote",
    "cpuProfiler",
    "flushRouterConfig",
    "rotateCertificates",
];

/// Outcome of classifying a `connectionStatus` reply.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PrivilegeReport {
    /// `user@db` of the authenticated users.
    pub users: Vec<String>,
    /// `role@db` of the authenticated roles.
    pub roles: Vec<String>,
    /// `resource: action` pairs of known write/admin actions.
    pub write_actions: Vec<String>,
    /// Actions on neither list (refused, fail-closed).
    pub unknown_actions: Vec<String>,
    /// Distinct actions held, for display.
    pub actions: Vec<String>,
    pub read_only: bool,
    /// Why the principal is refused, if it is.
    pub reason: Option<String>,
    /// Filled by the connector from `hello`: replica set (or sharded) → change streams available.
    #[serde(default)]
    pub replica_set: bool,
    #[serde(default)]
    pub set_name: Option<String>,
}

fn resource_label(r: &J) -> String {
    if r.get("cluster").and_then(J::as_bool) == Some(true) {
        return "cluster".into();
    }
    if r.get("anyResource").and_then(J::as_bool) == Some(true) {
        return "anyResource".into();
    }
    let db = r.get("db").and_then(J::as_str).unwrap_or("");
    let coll = r.get("collection").and_then(J::as_str).unwrap_or("");
    match (db, coll) {
        ("", "") => "any".into(),
        (db, "") => format!("{db}.*"),
        ("", c) => format!("*.{c}"),
        (db, c) => format!("{db}.{c}"),
    }
}

fn named(list: Option<&J>, key: &str) -> Vec<String> {
    list.and_then(J::as_array)
        .map(|a| {
            a.iter()
                .map(|u| {
                    format!(
                        "{}@{}",
                        u.get(key).and_then(J::as_str).unwrap_or("?"),
                        u.get("db").and_then(J::as_str).unwrap_or("?")
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Classifies the reply of `{connectionStatus: 1, showPrivileges: true}`.
///
/// An unauthenticated connection is refused: either auth is disabled (everyone can write) or the
/// connection cannot read anything.
pub fn classify_connection_status(reply: &J) -> PrivilegeReport {
    let auth = reply.get("authInfo").unwrap_or(&J::Null);
    let users = named(auth.get("authenticatedUsers"), "user");
    let roles = named(auth.get("authenticatedUserRoles"), "role");
    let mut write = BTreeSet::new();
    let mut unknown = BTreeSet::new();
    let mut actions = BTreeSet::new();
    for p in auth
        .get("authenticatedUserPrivileges")
        .and_then(J::as_array)
        .into_iter()
        .flatten()
    {
        let res = resource_label(p.get("resource").unwrap_or(&J::Null));
        for a in p
            .get("actions")
            .and_then(J::as_array)
            .into_iter()
            .flatten()
            .filter_map(J::as_str)
        {
            actions.insert(a.to_owned());
            if WRITE_ADMIN_ACTIONS.contains(&a) {
                write.insert(format!("{res}: {a}"));
            } else if !READ_ACTIONS.contains(&a) {
                unknown.insert(format!("{res}: {a}"));
            }
        }
    }
    let reason = if users.is_empty() {
        Some("connection is not authenticated (authentication disabled?); a dedicated read-only user is required".to_owned())
    } else if !write.is_empty() {
        Some(format!(
            "user holds write/admin actions: {}",
            write.iter().cloned().collect::<Vec<_>>().join(", ")
        ))
    } else if !unknown.is_empty() {
        Some(format!(
            "user holds actions outside the read-only allow-list: {}",
            unknown.iter().cloned().collect::<Vec<_>>().join(", ")
        ))
    } else {
        None
    };
    PrivilegeReport {
        users,
        roles,
        write_actions: write.into_iter().collect(),
        unknown_actions: unknown.into_iter().collect(),
        actions: actions.into_iter().collect(),
        read_only: reason.is_none(),
        reason,
        replica_set: false,
        set_name: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Shape of MongoDB 8.x's reply for a user with the built-in `read` role on `shop` (captured
    /// from the integration test's mongo:8 container).
    fn read_user() -> J {
        json!({
          "authInfo": {
            "authenticatedUsers": [{ "user": "caliban_ro", "db": "admin" }],
            "authenticatedUserRoles": [{ "role": "read", "db": "shop" }],
            "authenticatedUserPrivileges": [
              { "resource": { "db": "shop", "collection": "" },
                "actions": ["changeStream", "collStats", "dbHash", "dbStats", "find", "killCursors", "listCollections", "listIndexes", "listSearchIndexes", "performRawDataOperations", "planCacheRead"] },
              { "resource": { "db": "shop", "collection": "system.js" },
                "actions": ["changeStream", "collStats", "dbHash", "dbStats", "find", "killCursors", "listCollections", "listIndexes", "listSearchIndexes", "planCacheRead"] }
            ]
          },
          "ok": 1.0
        })
    }

    #[test]
    fn read_role_is_read_only() {
        let r = classify_connection_status(&read_user());
        assert!(r.read_only, "{r:?}");
        assert_eq!(r.users, vec!["caliban_ro@admin"]);
        assert_eq!(r.roles, vec!["read@shop"]);
        assert!(r.actions.contains(&"changeStream".to_string()));
    }

    #[test]
    fn read_write_role_is_refused() {
        let mut v = read_user();
        v["authInfo"]["authenticatedUserRoles"] = json!([{ "role": "readWrite", "db": "shop" }]);
        v["authInfo"]["authenticatedUserPrivileges"][0]["actions"] = json!([
            "find",
            "insert",
            "update",
            "remove",
            "createIndex",
            "dropCollection",
            "createCollection"
        ]);
        let r = classify_connection_status(&v);
        assert!(!r.read_only);
        assert!(
            r.write_actions.contains(&"shop.*: insert".to_string()),
            "{r:?}"
        );
        assert!(r.write_actions.contains(&"shop.*: createIndex".to_string()));
        assert!(r.reason.unwrap().contains("write/admin"));
    }

    #[test]
    fn root_and_unknown_actions_are_refused() {
        let root = json!({ "authInfo": {
            "authenticatedUsers": [{ "user": "admin", "db": "admin" }],
            "authenticatedUserRoles": [{ "role": "root", "db": "admin" }],
            "authenticatedUserPrivileges": [{ "resource": { "anyResource": true }, "actions": ["anyAction"] }] } });
        let r = classify_connection_status(&root);
        assert_eq!(r.write_actions, vec!["anyResource: anyAction"]);

        let odd = json!({ "authInfo": {
            "authenticatedUsers": [{ "user": "x", "db": "admin" }],
            "authenticatedUserPrivileges": [{ "resource": { "cluster": true }, "actions": ["find", "someFutureAction"] }] } });
        let r = classify_connection_status(&odd);
        assert!(!r.read_only);
        assert_eq!(r.unknown_actions, vec!["cluster: someFutureAction"]);
    }

    #[test]
    fn unauthenticated_is_refused() {
        let r = classify_connection_status(
            &json!({ "authInfo": { "authenticatedUsers": [], "authenticatedUserRoles": [] }, "ok": 1 }),
        );
        assert!(!r.read_only);
        assert!(r.reason.unwrap().contains("not authenticated"));
    }
}
