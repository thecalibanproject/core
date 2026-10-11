-- 0025: taint labels a run input carries from the start (P3 decision 8). See
-- crates/caliban-nodes/src/executor/taint.rs and docs/tools.md ("Taint").
--
-- Never edit an applied migration; add a new one.
--
-- `input_labels`: `["caller"]` when the run input holds untrusted caller data (fields the caller
-- marked, or that the node's input schema declares `x-caliban-untrusted`). Fixed when the run is
-- created, so a run replayed on another worker starts with the same labels. Metadata, not content.

ALTER TABLE node_run ADD COLUMN input_labels JSONB NOT NULL DEFAULT '[]';
