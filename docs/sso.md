# Admin access: single sign-on and roles

The control plane (`:8081`, admin API and web console) authenticates people and automation against
the customer's own OpenID Connect provider: Keycloak, Microsoft Entra ID, Okta, ADFS, Authentik,
Dex or any other compliant one. Nothing else is contacted: discovery, the signing keys (JWKS) and
the token endpoint all live on the issuer's origin, so it works on an air-gapped network with an
internal identity provider. Data-plane tenant API keys (`cal_...` on `/v1/*`) are a separate
mechanism and are not affected.

## How a request is authenticated

Checked in this order on every admin API route and on `/auth/me`:

1. **Break-glass token.** `Authorization: Bearer $CALIBAN_ADMIN_TOKEN` (or `[security] admin_token`).
   Owner rights. Without SSO this is "token mode", the way in for a first install. With SSO it is
   the emergency credential: every request made with it is logged at `warn` and audited as
   `auth.break_glass` (method and path), and everything it changes is audited with the actor
   `break_glass`. `break_glass = false` under `[security]` (or `CALIBAN_BREAK_GLASS=false`) turns
   it off once SSO works.
2. **Access tokens** (CI, scripts). `Authorization: Bearer <JWT>` issued by the configured issuer for
   `api_audience`. Validated like ID tokens (signature, `iss`, `aud`, `exp`, `nbf`, future `iat`),
   and ID tokens are refused. Only accepted when `api_audience` is set.
3. **Console session.** The cookie set by `/auth/callback`. Requests that change something
   (`POST`, `PUT`, `PATCH`, `DELETE`) must also send `X-CSRF-Token` (from `/auth/me`), and a
   browser `Origin` other than the console's is refused.

## Login (the control plane as backend for the console)

| Endpoint | What it does |
|---|---|
| `GET /auth/config` | Public: `{sso_enabled, break_glass_enabled, login_url}`, so the console knows what to offer |
| `GET /auth/login?return_to=/#/tenants` | Starts the authorization code flow with PKCE (S256). State, nonce and verifier are stored server-side for 10 minutes and bound to the browser with a short-lived `HttpOnly`, `SameSite=Lax` login cookie |
| `GET /auth/callback` | Checks the state (single use), the login cookie and the expiry, exchanges the code (`client_secret_basic`, or `client_secret_post` when the provider only supports that), validates the ID token (signature, `iss`, `aud` = client id, `azp`, `exp`, `nbf`, `iat`, `nonce`), creates or refreshes the user, creates the session and redirects to `return_to` (same-origin paths only) |
| `POST /auth/logout` | Revokes the session (CSRF-checked), clears the cookie and returns `{end_session_url}` for RP-initiated logout at the provider (`null` if it has none) |
| `GET /auth/me` | The caller: method (`session`, `bearer`, `break_glass`), user, groups, roles, effective permissions (`deployment` and per tenant), and for sessions the CSRF token and expiry |

Tokens from the provider never reach the browser. The session cookie is `HttpOnly`,
`SameSite=Strict`, `Path=/`, and `Secure` with the `__Host-` prefix when `redirect_url` is `https`
(a plain `http` console, for local development only, gets neither). Sessions are server-side
(Postgres table `auth_session`, keyed by the SHA-256 of the cookie token) with an absolute
lifetime (`session_ttl_secs`, default 8 h), an idle timeout (`session_idle_secs`, default 1 h) and
revocation (logout, or `DELETE /api/v1/users/{id}/sessions`). Expired sessions and pending logins
are purged every 10 minutes. Several control-plane replicas share sessions through Postgres.

Signing keys are cached for `jwks_cache_secs` (default 1 h). A token signed with an unknown key id
refetches the JWKS at once (at most every 30 s), so provider key rotation needs no restart; a
retired key stops being accepted when the cache next refreshes. Clock skew tolerance is
`clock_skew_secs` (default 60). Accepted algorithms: RS256/384/512, PS256/384/512, ES256/384 and
EdDSA; `none` and shared-secret (HS*) tokens are refused.

Failed logins are audited (`auth.login_failed`, with the reason: `issuer`, `audience`, `nonce`,
`expired`, `signature`, `unknown_key`, `browser_mismatch`, `idp_error`, `token_exchange`, ...)
when they belong to a login started in that browser. A callback with an unknown state is only
logged, so anonymous requests cannot grow the audit log.

## Roles

| Role | Scope | Can |
|---|---|---|
| `owner` | deployment | Everything, including granting and revoking `owner` |
| `admin` | deployment | Everything except granting or revoking `owner` |
| `auditor` | deployment | Read everything, including the audit log, users and role bindings; probe provider health |
| `tenant_admin` | one tenant | Tenant settings, API keys, BYOK keys, routes, datasources, ontology review, nodes (publishing included), usage |
| `developer` | one tenant | API keys, routes, node drafts and runs, and ontology review; reads the rest of the tenant (not BYOK secrets, which are never readable) |
| `viewer` | one tenant | Read-only access to the tenant |
| `billing` | one tenant | The tenant and its usage and spend |

Every role (tenant roles included) can read the model catalogue and the shared provider list.

Node permissions ([nodes](nodes.md)): `nodes.read` (versions and diffs), `nodes.write` (create
drafts, delete drafts and retired versions), `nodes.publish` (publish, promote, retire) and
`nodes.run` (run nodes; on the admin API, granting node access to an API key needs it):

| Role | `nodes.read` | `nodes.write` | `nodes.publish` | `nodes.run` |
|---|---|---|---|---|
| `owner`, `admin` | yes | yes | yes | yes |
| `tenant_admin` | yes | yes | yes | yes |
| `developer` | yes | yes | no | yes |
| `viewer`, `auditor` | yes | no | no | no |
| `billing` | no | no | no | no |

Run permissions (the console's [run endpoints](nodes.md#console-endpoints)): `runs.read` (run
lists, the inbox, run metadata: steps, timings, tokens, cost, taint labels), `runs.data` (run
content: inputs, outputs, questions; it is the tenant's data and may hold personal data) and
`runs.answer` (answer a question, approve or deny a tainted write, as oneself):

| Role | `runs.read` | `runs.data` | `runs.answer` |
|---|---|---|---|
| `owner`, `admin` | yes | yes | yes |
| `tenant_admin` | yes | yes | yes |
| `developer` | yes | yes | no |
| `viewer`, `auditor` | yes | no | no |
| `billing` | no | no | no |

Tool permissions ([tools](tools.md)): `tools.read`, `tools.write`, `tools.approve`; owner, admin and
`tenant_admin` hold all three, `developer` read and write, `viewer` and `auditor` read.
Roles come from three places and add up:

- **Group mappings in the config file** (`[[security.oidc.role_mappings]]`, or
  `CALIBAN_OIDC_OWNER_GROUPS` / `_ADMIN_GROUPS` / `_AUDITOR_GROUPS`): members of an IdP group get a
  role. Read-only in the console.
- **Group bindings** stored through the API (`subject_kind: "group"`).
- **User bindings** stored through the API (`subject_kind: "user"`, the user's id). Users are
  created just in time on their first login or first access token, keyed by issuer and subject.

Roles are recomputed on every request (from the groups captured at login, or in the access
token), so a removed binding takes effect on the next request. Another control-plane replica sees
a binding change within its refresh interval (5 s). A user with no role can log in and sees an
empty console until someone grants one.

Group names are matched exactly as the provider sends them in `groups_claim`. Deleting a tenant
removes the role bindings for it.

## Route permissions

Deny by default: every admin route has exactly one entry in the route table
(`crates/caliban-cp/src/auth/rbac.rs`); a route without one is refused to everybody, break-glass
included. Tenant-scoped permissions are checked against the tenant the request is about (the
`{tenantId}` path segment, the `tenant_id` query parameter or body field, or the tenant that owns
the datasource or ontology element). List endpoints without a tenant filter return only the
tenants the caller may see. A refusal is `403` with `error.type = "permission_error"`.

| Route | Permission | Allowed roles |
|---|---|---|
| `GET /api/v1/tenants` | `tenant.read` (list, filtered) | every role |
| `POST /api/v1/tenants` | `tenants.create` | owner, admin |
| `GET /api/v1/tenants/{tenantId}` | `tenant.read` | every role |
| `PATCH /api/v1/tenants/{tenantId}` | `tenant.write` | owner, admin, tenant_admin |
| `DELETE /api/v1/tenants/{tenantId}` | `tenant.delete` | owner, admin |
| `GET /api/v1/tenants/{tenantId}/api-keys` | `api_keys.read` | owner, admin, auditor, tenant_admin, developer, viewer |
| `POST /api/v1/tenants/{tenantId}/api-keys` | `api_keys.write` | owner, admin, tenant_admin, developer |
| `DELETE /api/v1/tenants/{tenantId}/api-keys/{keyId}` | `api_keys.write` | owner, admin, tenant_admin, developer |
| `PATCH /api/v1/tenants/{tenantId}/api-keys/{keyId}` | `api_keys.write` (`nodes.run` too to change node access) | owner, admin, tenant_admin, developer |
| `GET /api/v1/tenants/{tenantId}/provider-keys` | `provider_keys.read` | owner, admin, auditor, tenant_admin, developer, viewer |
| `POST /api/v1/tenants/{tenantId}/provider-keys` | `provider_keys.write` | owner, admin, tenant_admin |
| `DELETE /api/v1/tenants/{tenantId}/provider-keys/{keyId}` | `provider_keys.write` | owner, admin, tenant_admin |
| `GET /api/v1/tenants/{tenantId}/routes` | `routes.read` | owner, admin, auditor, tenant_admin, developer, viewer |
| `PUT /api/v1/tenants/{tenantId}/routes` | `routes.write` | owner, admin, tenant_admin, developer |
| `DELETE /api/v1/tenants/{tenantId}/datasources/{datasourceId}` | `datasources.write` | owner, admin, tenant_admin |
| `DELETE /api/v1/tenants/{tenantId}/nodes/{nodeId}` | `nodes.write` | owner, admin, tenant_admin, developer |
| `GET /api/v1/tenants/{tenantId}/nodes/{nodeName}/versions` | `nodes.read` | owner, admin, auditor, tenant_admin, developer, viewer |
| `POST /api/v1/tenants/{tenantId}/nodes/{nodeName}/versions` | `nodes.write` | owner, admin, tenant_admin, developer |
| `GET /api/v1/tenants/{tenantId}/nodes/{nodeName}/versions/{version}` | `nodes.read` | owner, admin, auditor, tenant_admin, developer, viewer |
| `POST /api/v1/tenants/{tenantId}/nodes/{nodeName}/versions/{version}/publish` | `nodes.publish` | owner, admin, tenant_admin |
| `POST /api/v1/tenants/{tenantId}/nodes/{nodeName}/versions/{version}/retire` | `nodes.publish` | owner, admin, tenant_admin |
| `POST /api/v1/tenants/{tenantId}/nodes/{nodeName}/promote` | `nodes.publish` | owner, admin, tenant_admin |
| `GET /api/v1/tenants/{tenantId}/nodes/{nodeName}/diff` | `nodes.read` | owner, admin, auditor, tenant_admin, developer, viewer |
| `GET /api/v1/tenants/{tenantId}/tool-servers` | `tools.read` | owner, admin, auditor, tenant_admin, developer, viewer |
| `POST /api/v1/tenants/{tenantId}/tool-servers` | `tools.write` | owner, admin, tenant_admin, developer |
| `DELETE /api/v1/tenants/{tenantId}/tool-servers/{server}` | `tools.write` | owner, admin, tenant_admin, developer |
| `POST /api/v1/tenants/{tenantId}/tool-servers/{server}/discover` | `tools.write` | owner, admin, tenant_admin, developer |
| `GET /api/v1/tenants/{tenantId}/tool-servers/{server}/tools` | `tools.read` | owner, admin, auditor, tenant_admin, developer, viewer |
| `POST /api/v1/tenants/{tenantId}/tool-servers/{server}/tools` | `tools.write` | owner, admin, tenant_admin, developer |
| `POST /api/v1/tenants/{tenantId}/tool-servers/{server}/tools/{tool}/approve` | `tools.approve` | owner, admin, tenant_admin |
| `POST /api/v1/tenants/{tenantId}/tool-servers/{server}/tools/{tool}/revoke` | `tools.approve` | owner, admin, tenant_admin |
| `GET /api/v1/tenants/{tenantId}/runs` | `runs.read` | owner, admin, auditor, tenant_admin, developer, viewer |
| `GET /api/v1/tenants/{tenantId}/runs/{runId}` | `runs.read` (content with `runs.data`) | owner, admin, auditor, tenant_admin, developer, viewer |
| `POST /api/v1/tenants/{tenantId}/runs/{runId}/input` | `runs.answer` | owner, admin, tenant_admin |
| `GET /api/v1/tenants/{tenantId}/inbox` | `runs.read` (questions with `runs.data`) | owner, admin, auditor, tenant_admin, developer, viewer |
| `GET /api/v1/models` | `catalog.read` | every role |
| `POST /api/v1/models` | `catalog.write` | owner, admin |
| `DELETE /api/v1/models/{modelId}` | `catalog.write` | owner, admin |
| `GET /api/v1/providers` | `catalog.read` | every role |
| `POST /api/v1/providers` | `catalog.write` | owner, admin |
| `DELETE /api/v1/providers/{providerId}` | `catalog.write` | owner, admin |
| `GET /api/v1/providers/{providerId}/health` | `providers.probe` | owner, admin, auditor |
| `POST /api/v1/providers/{providerId}/discover` | `catalog.write` | owner, admin |
| `GET /api/v1/datasources` | `datasources.read` (`?tenant_id=` or list, filtered) | owner, admin, auditor, tenant_admin, developer, viewer |
| `POST /api/v1/datasources` | `datasources.write` (body `tenant_id`) | owner, admin, tenant_admin |
| `POST /api/v1/datasources/{datasourceId}/introspect` | `datasources.write` (the datasource's tenant) | owner, admin, tenant_admin |
| `GET /api/v1/ontology?tenant_id=` | `ontology.read` | owner, admin, auditor, tenant_admin, developer, viewer |
| `POST /api/v1/ontology/elements/{elementId}/review` | `ontology.review` (the element's tenant) | owner, admin, tenant_admin, developer |
| `GET /api/v1/nodes` | `nodes.read` (`?tenant_id=` or list, filtered) | owner, admin, auditor, tenant_admin, developer, viewer |
| `POST /api/v1/nodes` | `nodes.write` (body `tenant_id`) | owner, admin, tenant_admin, developer |
| `GET /api/v1/usage` | `usage.read` (`?tenant_id=` or all visible tenants) | every role |
| `GET /api/v1/audit` | `audit.read` | owner, admin, auditor |
| `GET /api/v1/keys/status` | `audit.read` | owner, admin, auditor |
| `GET /api/v1/roles` | `rbac.read` | owner, admin, auditor |
| `GET /api/v1/users` | `rbac.read` | owner, admin, auditor |
| `DELETE /api/v1/users/{userId}/sessions` | `rbac.write` | owner, admin |
| `GET /api/v1/role-bindings` | `rbac.read` | owner, admin, auditor |
| `POST /api/v1/role-bindings` | `rbac.write` (`owner` bindings: owner only) | owner, admin |
| `DELETE /api/v1/role-bindings/{bindingId}` | `rbac.write` (`owner` bindings: owner only) | owner, admin |
| `GET /api/v1/health` | none (public) | anyone |
| `GET /api/v1/snapshot` | router token, not a user | split-mode routers |
| `POST /api/v1/usage/ingest`, `POST /api/v1/audit/ingest` | router token, not a user | split-mode routers and workers |

"Every role" means any of the seven roles (tenant roles for their own tenant on tenant-scoped
routes). The test `auth::tests::every_role_against_every_admin_route` checks this table against
every role on its own tenant and on another one.

## Audit

The audit actor is the user, written `email <issuer#subject>` (the name or the subject when there
is no email; the part in angle brackets is the stable identity), `break_glass` for the bootstrap
token and `system` for startup work. Recorded actions, besides every configuration change:
`auth.login`, `auth.logout`, `auth.login_failed`, `auth.break_glass`, `user.create` (first access
token), `user.sessions_revoke`, `role_binding.create` and `role_binding.delete`. Rows stay in the
same SHA-256 hash chain. Tokens, cookies and client secrets are never recorded.

## Configuration

```toml
[security]
admin_token = { env = "CALIBAN_ADMIN_TOKEN" }   # break-glass once SSO works
# break_glass = false                           # turn the token off entirely

[security.oidc]
issuer = "https://keycloak.example.internal/realms/caliban"   # exactly as discovery reports it
client_id = "caliban-console"
client_secret = { env = "CALIBAN_OIDC_CLIENT_SECRET" }        # or { file = "..." } or { sealed = "..." }
redirect_url = "https://caliban.example.internal/auth/callback"
scopes = ["openid", "profile", "email"]                       # the default
groups_claim = "groups"                                       # dotted path for nested claims
api_audience = "caliban-api"                                  # accept access tokens for this audience
# session_ttl_secs = 28800
# session_idle_secs = 3600
# clock_skew_secs = 60
# jwks_cache_secs = 3600
# ca_file = "/etc/caliban/idp-ca.pem"                         # internal PKI
# post_logout_redirect_url = "https://caliban.example.internal/"

[[security.oidc.role_mappings]]
group = "caliban-owners"
role = "owner"

[[security.oidc.role_mappings]]
group = "acme-developers"
role = "developer"
tenant = "acme"
```

Environment overrides (handy for Compose and Helm; with no `[security.oidc]` section,
`CALIBAN_OIDC_ISSUER` turns SSO on and the client id and redirect URL become required):
`CALIBAN_OIDC_ISSUER`, `CALIBAN_OIDC_CLIENT_ID`, `CALIBAN_OIDC_CLIENT_SECRET` (the secret itself;
the config then references it), `CALIBAN_OIDC_REDIRECT_URL`, `CALIBAN_OIDC_SCOPES` (space or comma
separated), `CALIBAN_OIDC_GROUPS_CLAIM`, `CALIBAN_OIDC_API_AUDIENCE`, `CALIBAN_OIDC_CA_FILE`,
`CALIBAN_OIDC_OWNER_GROUPS`, `CALIBAN_OIDC_ADMIN_GROUPS`, `CALIBAN_OIDC_AUDITOR_GROUPS` (comma
separated) and `CALIBAN_BREAK_GLASS`.

The issuer, the redirect URL and the client secret are checked at startup. The provider is
contacted lazily, so a control plane starts (and break-glass works) while the provider is down.
An `http` issuer or redirect URL is accepted with a warning, for development.

**First run.** Start without SSO and log in with the admin token, or set
`CALIBAN_OIDC_OWNER_GROUPS` to a group you are in. Once an owner can log in through SSO, set
`break_glass = false` or keep the token offline for emergencies (every use is audited).

## Keycloak

1. In the realm, **Clients → Create client**: type OpenID Connect, client ID `caliban-console`.
   Turn **Client authentication** on (confidential client) and keep only **Standard flow**.
2. **Valid redirect URIs**: `https://caliban.example.internal/auth/callback`. **Valid post logout
   redirect URIs**: `https://caliban.example.internal/`. Under **Advanced**, set **Proof Key for
   Code Exchange Code Challenge Method** to `S256`.
3. **Credentials** tab: copy the client secret into `CALIBAN_OIDC_CLIENT_SECRET`.
4. Groups in the token: **Client scopes → caliban-console-dedicated → Add mapper → By
   configuration → Group Membership**, token claim name `groups`, **Full group path** off, added to
   the ID token and the access token. (Realm roles instead: `groups_claim = "realm_access.roles"`.)
5. Issuer: `https://<keycloak host>/realms/<realm>`.
6. Automation: create a client `caliban-ci` with client authentication and **Service account
   roles** on. In its dedicated scope add an **Audience** mapper with custom audience
   `caliban-api` (and the group mapper), put its service account user in a mapped group, and set
   `api_audience = "caliban-api"`. A job then runs:
   ```sh
   TOKEN=$(curl -s -u caliban-ci:$CI_SECRET -d grant_type=client_credentials \
     https://keycloak.example.internal/realms/caliban/protocol/openid-connect/token | jq -r .access_token)
   curl -H "Authorization: Bearer $TOKEN" https://caliban.example.internal/api/v1/tenants
   ```

## Microsoft Entra ID

1. **App registrations → New registration**: single tenant, redirect URI of type **Web**:
   `https://caliban.example.internal/auth/callback`. Leave **ID tokens (implicit flow)** unchecked.
2. **Certificates & secrets → New client secret** into `CALIBAN_OIDC_CLIENT_SECRET` (it expires:
   rotate it before then).
3. Issuer: `https://login.microsoftonline.com/<directory (tenant) id>/v2.0`; client ID: the
   application (client) ID. Multi-tenant (`common`, `organizations`) issuers are not supported.
4. Roles: prefer **App roles** (for example `caliban.owner`, `caliban.acme.developer`), assigned to
   users or groups under **Enterprise applications → Users and groups**, with
   `groups_claim = "roles"` and the role values in `role_mappings`. Entra's `groups` claim carries
   group object IDs (GUIDs, not names), and above 200 groups it is replaced by a Graph link that
   Caliban does not follow (it calls nothing but the issuer). If you use groups, add the claim
   under **Token configuration → Add groups claim** and map the object IDs.
5. Email: add the optional claim `email` to the ID token under **Token configuration**; otherwise
   the audit log shows the name or `preferred_username`.
6. Automation: **Expose an API** with application ID URI `api://<client id>`, add an app role
   allowed for **Applications**, register a CI app with a secret, grant it that role under **API
   permissions** (admin consent), and request tokens with
   `scope=api://<client id>/.default` and the client credentials grant. Set `api_audience` to the
   token's `aud`: `api://<client id>` for v1 access tokens, or the client id when the manifest sets
   `accessTokenAcceptedVersion: 2` (Caliban then refuses ID tokens by their `nonce`).

## Limits

- No userinfo call and no Microsoft Graph lookups: roles come from the token's claims.
- No refresh tokens: when a session ends, the user logs in again (usually silent at the provider).
- Back-channel and front-channel logout from the provider are not implemented; RP-initiated logout
  is.
- One issuer per deployment.
- The discovery document's endpoints must be on the issuer's origin.
- Tenant admins cannot yet grant roles on their own tenant; owners and admins do.
