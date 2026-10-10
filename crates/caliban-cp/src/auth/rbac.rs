//! Roles, permissions and the admin API route table.
//!
//! Deployment roles apply to the whole installation: `owner`, `admin` and `auditor` (read-only,
//! audit log included). Tenant roles apply to one tenant: `tenant_admin`, `developer`, `viewer` and
//! `billing`. A principal holds any number of both; what it may do is the union.
//!
//! Every admin API route has exactly one entry in [`ROUTES`]; a route without one is denied to
//! everybody (deny by default). Tenant-scoped permissions are checked against the tenant the
//! request is about, found as [`TenantFrom`] says. List endpoints without a tenant filter return
//! only the tenants the principal may see.

use serde::{Deserialize, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Owner,
    Admin,
    Auditor,
    TenantAdmin,
    Developer,
    Viewer,
    Billing,
}

impl Role {
    pub const ALL: [Role; 7] =
        [Role::Owner, Role::Admin, Role::Auditor, Role::TenantAdmin, Role::Developer, Role::Viewer, Role::Billing];

    pub fn as_str(self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::Auditor => "auditor",
            Role::TenantAdmin => "tenant_admin",
            Role::Developer => "developer",
            Role::Viewer => "viewer",
            Role::Billing => "billing",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        Role::ALL.into_iter().find(|r| r.as_str() == s)
    }

    pub fn is_tenant_role(self) -> bool {
        matches!(self, Role::TenantAdmin | Role::Developer | Role::Viewer | Role::Billing)
    }

    pub fn description(self) -> &'static str {
        match self {
            Role::Owner => "Everything, including granting and revoking the owner role.",
            Role::Admin => "Everything except granting or revoking the owner role.",
            Role::Auditor => "Read-only access to everything, including the audit log.",
            Role::TenantAdmin => "Manages one tenant: settings, API keys, BYOK keys, routes, datasources, nodes.",
            Role::Developer => "API keys, routes, nodes and ontology review of one tenant; reads the rest.",
            Role::Viewer => "Read-only access to one tenant.",
            Role::Billing => "Usage and spend of one tenant.",
        }
    }

    /// The permissions this role grants (on its tenant, for tenant roles).
    pub fn permissions(self) -> &'static [Perm] {
        use Perm::*;
        match self {
            Role::Owner | Role::Admin => &Perm::ALL,
            Role::Auditor => &[
                CatalogRead,
                ProvidersProbe,
                AuditRead,
                RbacRead,
                TenantRead,
                ApiKeysRead,
                ProviderKeysRead,
                RoutesRead,
                DatasourcesRead,
                OntologyRead,
                NodesRead,
                UsageRead,
            ],
            Role::TenantAdmin => &[
                CatalogRead,
                TenantRead,
                TenantWrite,
                ApiKeysRead,
                ApiKeysWrite,
                ProviderKeysRead,
                ProviderKeysWrite,
                RoutesRead,
                RoutesWrite,
                DatasourcesRead,
                DatasourcesWrite,
                OntologyRead,
                OntologyReview,
                NodesRead,
                NodesWrite,
                UsageRead,
            ],
            Role::Developer => &[
                CatalogRead,
                TenantRead,
                ApiKeysRead,
                ApiKeysWrite,
                ProviderKeysRead,
                RoutesRead,
                RoutesWrite,
                DatasourcesRead,
                OntologyRead,
                OntologyReview,
                NodesRead,
                NodesWrite,
                UsageRead,
            ],
            Role::Viewer => &[
                CatalogRead,
                TenantRead,
                ApiKeysRead,
                ProviderKeysRead,
                RoutesRead,
                DatasourcesRead,
                OntologyRead,
                NodesRead,
                UsageRead,
            ],
            Role::Billing => &[CatalogRead, TenantRead, UsageRead],
        }
    }

    pub fn grants(self, p: Perm) -> bool {
        self.permissions().contains(&p)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Perm {
    // Deployment-wide.
    TenantsCreate,
    CatalogRead,
    CatalogWrite,
    ProvidersProbe,
    AuditRead,
    RbacRead,
    RbacWrite,
    // Per tenant.
    TenantRead,
    TenantWrite,
    TenantDelete,
    ApiKeysRead,
    ApiKeysWrite,
    ProviderKeysRead,
    ProviderKeysWrite,
    RoutesRead,
    RoutesWrite,
    DatasourcesRead,
    DatasourcesWrite,
    OntologyRead,
    OntologyReview,
    NodesRead,
    NodesWrite,
    UsageRead,
}

impl Perm {
    pub const ALL: [Perm; 23] = [
        Perm::TenantsCreate,
        Perm::CatalogRead,
        Perm::CatalogWrite,
        Perm::ProvidersProbe,
        Perm::AuditRead,
        Perm::RbacRead,
        Perm::RbacWrite,
        Perm::TenantRead,
        Perm::TenantWrite,
        Perm::TenantDelete,
        Perm::ApiKeysRead,
        Perm::ApiKeysWrite,
        Perm::ProviderKeysRead,
        Perm::ProviderKeysWrite,
        Perm::RoutesRead,
        Perm::RoutesWrite,
        Perm::DatasourcesRead,
        Perm::DatasourcesWrite,
        Perm::OntologyRead,
        Perm::OntologyReview,
        Perm::NodesRead,
        Perm::NodesWrite,
        Perm::UsageRead,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Perm::TenantsCreate => "tenants.create",
            Perm::CatalogRead => "catalog.read",
            Perm::CatalogWrite => "catalog.write",
            Perm::ProvidersProbe => "providers.probe",
            Perm::AuditRead => "audit.read",
            Perm::RbacRead => "rbac.read",
            Perm::RbacWrite => "rbac.write",
            Perm::TenantRead => "tenant.read",
            Perm::TenantWrite => "tenant.write",
            Perm::TenantDelete => "tenant.delete",
            Perm::ApiKeysRead => "api_keys.read",
            Perm::ApiKeysWrite => "api_keys.write",
            Perm::ProviderKeysRead => "provider_keys.read",
            Perm::ProviderKeysWrite => "provider_keys.write",
            Perm::RoutesRead => "routes.read",
            Perm::RoutesWrite => "routes.write",
            Perm::DatasourcesRead => "datasources.read",
            Perm::DatasourcesWrite => "datasources.write",
            Perm::OntologyRead => "ontology.read",
            Perm::OntologyReview => "ontology.review",
            Perm::NodesRead => "nodes.read",
            Perm::NodesWrite => "nodes.write",
            Perm::UsageRead => "usage.read",
        }
    }

    /// Checked against a tenant (tenant roles can hold it); otherwise deployment-wide.
    pub fn is_tenant_scoped(self) -> bool {
        !matches!(
            self,
            Perm::TenantsCreate
                | Perm::CatalogRead
                | Perm::CatalogWrite
                | Perm::ProvidersProbe
                | Perm::AuditRead
                | Perm::RbacRead
                | Perm::RbacWrite
        )
    }
}

impl Serialize for Perm {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

/// Roles held by a principal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Grants {
    pub deployment: BTreeSet<Role>,
    pub tenants: BTreeMap<String, BTreeSet<Role>>,
}

/// Which tenants a principal may see for a permission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Visible {
    All,
    Only(BTreeSet<String>),
}

impl Visible {
    pub fn contains(&self, tenant: &str) -> bool {
        match self {
            Visible::All => true,
            Visible::Only(s) => s.contains(tenant),
        }
    }
}

impl Grants {
    pub fn owner() -> Self {
        let mut g = Grants::default();
        g.deployment.insert(Role::Owner);
        g
    }

    /// Adds a role. A tenant role without a tenant, or a deployment role with one, is ignored
    /// (config and store validation reject both before they get here).
    pub fn add(&mut self, role: Role, tenant: Option<&str>) {
        match (role.is_tenant_role(), tenant) {
            (false, None) => {
                self.deployment.insert(role);
            }
            (true, Some(t)) => {
                self.tenants.entry(t.to_owned()).or_default().insert(role);
            }
            _ => {}
        }
    }

    pub fn is_empty(&self) -> bool {
        self.deployment.is_empty() && self.tenants.is_empty()
    }

    pub fn has(&self, role: Role) -> bool {
        self.deployment.contains(&role)
    }

    /// May the principal do `p` (on `tenant`, for tenant-scoped permissions)? Deployment roles
    /// apply to every tenant. Deployment-wide permissions granted by tenant roles (reading the
    /// model catalogue) hold whichever tenant grants them.
    pub fn allows(&self, p: Perm, tenant: Option<&str>) -> bool {
        if self.deployment.iter().any(|r| r.grants(p)) {
            return true;
        }
        if !p.is_tenant_scoped() {
            return self.tenants.values().flatten().any(|r| r.grants(p));
        }
        tenant.and_then(|t| self.tenants.get(t)).is_some_and(|roles| roles.iter().any(|r| r.grants(p)))
    }

    /// Holds `p` deployment-wide or on at least one tenant.
    pub fn allows_somewhere(&self, p: Perm) -> bool {
        self.deployment.iter().chain(self.tenants.values().flatten()).any(|r| r.grants(p))
    }

    pub fn visible(&self, p: Perm) -> Visible {
        if self.deployment.iter().any(|r| r.grants(p)) {
            return Visible::All;
        }
        Visible::Only(
            self.tenants
                .iter()
                .filter(|(_, roles)| roles.iter().any(|r| r.grants(p)))
                .map(|(t, _)| t.clone())
                .collect(),
        )
    }

    /// Permissions held deployment-wide (they apply to every tenant), and per tenant.
    pub fn permissions(&self) -> (BTreeSet<Perm>, BTreeMap<String, BTreeSet<Perm>>) {
        let deployment: BTreeSet<Perm> = Perm::ALL
            .into_iter()
            .filter(|p| {
                self.deployment.iter().any(|r| r.grants(*p)) || (!p.is_tenant_scoped() && self.allows(*p, None))
            })
            .collect();
        let tenants = self
            .tenants
            .iter()
            .map(|(t, roles)| {
                let ps = roles
                    .iter()
                    .flat_map(|r| r.permissions().iter().copied())
                    .filter(|p| p.is_tenant_scoped() && !deployment.contains(p))
                    .collect();
                (t.clone(), ps)
            })
            .collect();
        (deployment, tenants)
    }
}

/// Where a route's tenant comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantFrom {
    /// Deployment-wide permission: no tenant.
    None,
    /// The `{tenant_id}` path parameter.
    Path,
    /// `?tenant_id=`; without it the route lists across tenants and filters by visibility.
    QueryOrList,
    /// A list across tenants, filtered by visibility.
    List,
    /// The `tenant_id` field of the JSON body.
    Body,
    /// The tenant of the datasource `{id}`.
    Datasource,
    /// The tenant of the ontology element `{id}`.
    OntologyElement,
}

#[derive(Debug, Clone, Copy)]
pub struct RouteRule {
    pub method: &'static str,
    /// Axum route syntax, relative to `/api/v1`.
    pub path: &'static str,
    pub perm: Perm,
    pub tenant: TenantFrom,
}

const fn r(method: &'static str, path: &'static str, perm: Perm, tenant: TenantFrom) -> RouteRule {
    RouteRule { method, path, perm, tenant }
}

/// Every admin API route and the permission it needs. `/health` and `/snapshot` are not here:
/// the first is public, the second takes the router token.
pub const ROUTES: &[RouteRule] = &[
    r("GET", "/tenants", Perm::TenantRead, TenantFrom::List),
    r("POST", "/tenants", Perm::TenantsCreate, TenantFrom::None),
    r("GET", "/tenants/{tenant_id}", Perm::TenantRead, TenantFrom::Path),
    r("PATCH", "/tenants/{tenant_id}", Perm::TenantWrite, TenantFrom::Path),
    r("DELETE", "/tenants/{tenant_id}", Perm::TenantDelete, TenantFrom::Path),
    r("GET", "/tenants/{tenant_id}/api-keys", Perm::ApiKeysRead, TenantFrom::Path),
    r("POST", "/tenants/{tenant_id}/api-keys", Perm::ApiKeysWrite, TenantFrom::Path),
    r("DELETE", "/tenants/{tenant_id}/api-keys/{key_id}", Perm::ApiKeysWrite, TenantFrom::Path),
    r("GET", "/tenants/{tenant_id}/provider-keys", Perm::ProviderKeysRead, TenantFrom::Path),
    r("POST", "/tenants/{tenant_id}/provider-keys", Perm::ProviderKeysWrite, TenantFrom::Path),
    r("DELETE", "/tenants/{tenant_id}/provider-keys/{key_id}", Perm::ProviderKeysWrite, TenantFrom::Path),
    r("GET", "/tenants/{tenant_id}/routes", Perm::RoutesRead, TenantFrom::Path),
    r("PUT", "/tenants/{tenant_id}/routes", Perm::RoutesWrite, TenantFrom::Path),
    r("DELETE", "/tenants/{tenant_id}/datasources/{id}", Perm::DatasourcesWrite, TenantFrom::Path),
    r("DELETE", "/tenants/{tenant_id}/nodes/{id}", Perm::NodesWrite, TenantFrom::Path),
    r("GET", "/models", Perm::CatalogRead, TenantFrom::None),
    r("POST", "/models", Perm::CatalogWrite, TenantFrom::None),
    r("DELETE", "/models/{*id}", Perm::CatalogWrite, TenantFrom::None),
    r("GET", "/providers", Perm::CatalogRead, TenantFrom::None),
    r("POST", "/providers", Perm::CatalogWrite, TenantFrom::None),
    r("DELETE", "/providers/{id}", Perm::CatalogWrite, TenantFrom::None),
    r("GET", "/providers/{id}/health", Perm::ProvidersProbe, TenantFrom::None),
    r("POST", "/providers/{id}/discover", Perm::CatalogWrite, TenantFrom::None),
    r("GET", "/datasources", Perm::DatasourcesRead, TenantFrom::QueryOrList),
    r("POST", "/datasources", Perm::DatasourcesWrite, TenantFrom::Body),
    r("POST", "/datasources/{id}/introspect", Perm::DatasourcesWrite, TenantFrom::Datasource),
    r("GET", "/ontology", Perm::OntologyRead, TenantFrom::QueryOrList),
    r("POST", "/ontology/elements/{id}/review", Perm::OntologyReview, TenantFrom::OntologyElement),
    r("GET", "/nodes", Perm::NodesRead, TenantFrom::QueryOrList),
    r("POST", "/nodes", Perm::NodesWrite, TenantFrom::Body),
    r("GET", "/usage", Perm::UsageRead, TenantFrom::QueryOrList),
    r("GET", "/audit", Perm::AuditRead, TenantFrom::None),
    r("GET", "/keys/status", Perm::AuditRead, TenantFrom::None),
    r("GET", "/roles", Perm::RbacRead, TenantFrom::None),
    r("GET", "/users", Perm::RbacRead, TenantFrom::None),
    r("DELETE", "/users/{id}/sessions", Perm::RbacWrite, TenantFrom::None),
    r("GET", "/role-bindings", Perm::RbacRead, TenantFrom::None),
    r("POST", "/role-bindings", Perm::RbacWrite, TenantFrom::None),
    r("DELETE", "/role-bindings/{id}", Perm::RbacWrite, TenantFrom::None),
];

/// The rule for a matched route (`path` as axum reports it, with or without the `/api/v1` prefix).
pub fn rule(method: &str, path: &str) -> Option<&'static RouteRule> {
    let path = path.strip_prefix("/api/v1").unwrap_or(path);
    ROUTES.iter().find(|r| r.method == method && r.path == path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_roles_cover_every_tenant() {
        let mut g = Grants::default();
        g.add(Role::Auditor, None);
        assert!(g.allows(Perm::ApiKeysRead, Some("anything")));
        assert!(!g.allows(Perm::ApiKeysWrite, Some("anything")));
        assert!(g.allows(Perm::AuditRead, None));
        assert_eq!(g.visible(Perm::UsageRead), Visible::All);
    }

    #[test]
    fn tenant_roles_stay_in_their_tenant() {
        let mut g = Grants::default();
        g.add(Role::Developer, Some("acme"));
        g.add(Role::Billing, Some("globex"));
        assert!(g.allows(Perm::ApiKeysWrite, Some("acme")));
        assert!(!g.allows(Perm::ApiKeysWrite, Some("globex")));
        assert!(!g.allows(Perm::ApiKeysWrite, None));
        assert!(g.allows(Perm::UsageRead, Some("globex")));
        assert!(g.allows(Perm::CatalogRead, None), "tenant roles read the model catalogue");
        assert!(!g.allows(Perm::CatalogWrite, None) && !g.allows(Perm::AuditRead, None));
        assert_eq!(g.visible(Perm::ApiKeysRead), Visible::Only(["acme".to_owned()].into()));
        assert_eq!(g.visible(Perm::UsageRead), Visible::Only(["acme".to_owned(), "globex".to_owned()].into()));
        // Mismatched scopes are ignored.
        let mut bad = Grants::default();
        bad.add(Role::Owner, Some("acme"));
        bad.add(Role::Viewer, None);
        assert!(bad.is_empty());
    }

    #[test]
    fn route_table_is_unambiguous() {
        for (i, a) in ROUTES.iter().enumerate() {
            assert!(!ROUTES[i + 1..].iter().any(|b| a.method == b.method && a.path == b.path), "{a:?}");
            assert_eq!(a.perm.is_tenant_scoped(), a.tenant != TenantFrom::None, "{a:?}");
        }
        assert_eq!(rule("GET", "/api/v1/tenants/{tenant_id}").unwrap().perm, Perm::TenantRead);
        assert!(rule("GET", "/api/v1/nope").is_none());
    }

    #[test]
    fn owner_and_admin_hold_everything() {
        let (d, t) = Grants::owner().permissions();
        assert_eq!(d.len(), Perm::ALL.len());
        assert!(t.is_empty());
        for r in Role::ALL {
            assert_eq!(Role::parse(r.as_str()), Some(r));
        }
    }
}
