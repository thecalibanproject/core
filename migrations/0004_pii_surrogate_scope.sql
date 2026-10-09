-- 0004: per-tenant PII surrogate scope (docs/architecture/caliban-reference-architecture.md §9).
--
-- Never edit an applied migration; add a new one.
--
-- 'tenant' (default): the same value in the same tenant always gets the same surrogate, derived
-- with a keyed HMAC under a per-tenant key (HKDF over CALIBAN_KEK, tenant id as info), so
-- pseudonymised requests can hit the exact cache. Sessions within the tenant become linkable
-- through their surrogates. 'session': fresh random surrogates per request (opt-in).
-- Surrogates never cross tenants either way. No surrogate-to-original table is stored: the
-- reverse map lives only for the request that produced it.

ALTER TABLE tenant
    ADD COLUMN pii_surrogate_scope TEXT NOT NULL DEFAULT 'tenant'
        CHECK (pii_surrogate_scope IN ('tenant', 'session'));
