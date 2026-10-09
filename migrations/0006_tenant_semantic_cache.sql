-- 0006: per-tenant switch for the T2 semantic cache (docs/research/01-semantic-caching-and-rust-vector-stack.md).
--
-- Never edit an applied migration; add a new one. (0005 is reserved.)
--
-- 'off' (default): the tenant's requests never use the semantic cache. 'on': eligible requests
-- (see the core README, "Cache") may be answered with the response to an earlier, semantically
-- similar request of the same tenant, under per-entry learned thresholds and the deployment's
-- error budget ([cache.semantic]). Entries never cross tenants either way.

ALTER TABLE tenant
    ADD COLUMN semantic_cache TEXT NOT NULL DEFAULT 'off'
        CHECK (semantic_cache IN ('off', 'on'));
