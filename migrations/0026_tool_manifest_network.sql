-- 0026: whether an approved tool reaches the network through its arguments (P3 decision 11). See
-- docs/tools.md ("Reads that reach the network").
--
-- Never edit an applied migration; add a new one.
--
-- `network`: the approver's decision, recorded with the approval. NULL: none was given, the tool's
-- input schema decides (a URL or host argument). A read tool that reaches the network is gated
-- like a write: tainted arguments need an allowlist entry or a human approval.

ALTER TABLE tool_manifest ADD COLUMN network BOOLEAN;
