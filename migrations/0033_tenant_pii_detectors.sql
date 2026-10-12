-- 0033: a tenant's own L0 PII detectors (research note 05, section 1: tenant dictionaries and
-- institutional identifiers). See crates/caliban-pii/src/dictionary.rs.
--
-- Never edit an applied migration; add a new one.
--
-- pii_patterns: [{label, pattern}] regexes for identifier formats the built-in patterns do not
-- know (a national ID format). pii_dictionary: [{term, label}] exact terms (customer names,
-- account ids, internal codes). Both are shipped to the data plane in the snapshot and run next
-- to the built-in detectors. NULL: none. The dictionary holds names a tenant chose to protect,
-- so it is tenant data like its datasource settings.

ALTER TABLE tenant
    ADD COLUMN pii_patterns   JSONB,
    ADD COLUMN pii_dictionary JSONB;
