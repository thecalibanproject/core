-- 0027: the per-tenant eval key (P3 decision 9). See crates/caliban-cp/src/evals.rs and
-- docs/evals.md ("The eval key").
--
-- Never edit an applied migration; add a new one.
--
-- `purpose`: NULL for keys customers create; 'eval' for the key the control plane creates and
-- manages for a tenant's evals. Its plaintext is never kept or shown (only the hash, like every
-- key), the data plane refuses it on its HTTP and MCP endpoints, and it is rotated with
-- `POST /api/v1/tenants/{t}/eval-key/rotate` or revoked with the tenant. At most one is active per
-- tenant.

ALTER TABLE api_key ADD COLUMN purpose TEXT CHECK (purpose IN ('eval'));
CREATE UNIQUE INDEX api_key_one_eval_key ON api_key (tenant_id) WHERE purpose = 'eval' AND revoked_at IS NULL;
