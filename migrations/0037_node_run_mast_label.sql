-- 0037: the MAST failure label a human gave a run (research note 04, section 6: "Trace UI lets
-- humans label failed runs with MAST categories. These labels feed the eval loop."). See
-- crates/caliban-nodes/src/eval/capture.rs and docs/evals.md ("Cases from runs").
--
-- Never edit an applied migration; add a new one.
--
-- node_run.mast_label: one of the 14 MAST failure modes (arXiv 2503.13657), by id
-- (`step_repetition`, `fail_to_ask_for_clarification`, ...), set when a run is captured into a
-- golden set as `bad` with a label. Metadata, never content. NULL when nobody labelled the run.

ALTER TABLE node_run ADD COLUMN mast_label TEXT;
