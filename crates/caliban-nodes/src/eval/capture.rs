//! Golden cases from runs: the production feedback loop of research note 04 §7 ("traces → MAST
//! labels + user feedback → regression sets") and §6 ("Trace UI lets humans label failed runs
//! with MAST categories. These labels feed the eval loop."). Golden sets are hand-written JSON
//! that real users will not write; a reviewer marks a finished run `good` or `bad` instead, and
//! the control plane appends a case built from it ([`case_from_run`]) to a golden set.
//!
//! **What a case holds.** The run's input; its human steps' answers as scripted `answers` (by
//! step id); checks derived from the run:
//!
//! - `json_schema` with the version's output schema, when it declares one;
//! - `good`: an `llm_judge` check with the run's output as its reference answer (the reviewer's
//!   note, when given, is part of the rubric), and a `tool_call` check for each write tool the run
//!   called (by its reference without the pin, arguments not asserted: they change between
//!   trials, and a tool not trusted with personal data receives surrogates);
//! - `bad`: an `llm_judge` check whose rubric is the reviewer's note on the right behaviour (the
//!   note is required), with the MAST failure mode when one was given. The run's writes are not
//!   asserted: the reviewer did not say which of them were the mistake.
//!
//! Tags record where it came from (`captured`, the verdict, the MAST label). The case id is the
//! run id, so a run is captured at most once into a set. Everything here is tenant content: the
//! case goes into the sealed golden set, never into an audit entry or a log (note 05).

use super::sandbox::OBSERVATION;
use super::{Check, GoldenCase};
use crate::journal::{Journal, RunRecord, RunStatus, WRITE_EVENT};
use crate::seal::Sealer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A reviewer's verdict on a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The run did the right thing: its output is the reference.
    Good,
    /// The run went wrong: the note says what the right behaviour is.
    Bad,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Bad => "bad",
        }
    }
}

/// One failure mode of MAST (Cemri et al., "Why Do Multi-Agent LLM Systems Fail?", arXiv
/// 2503.13657): 14 modes in 3 classes, the failure-label taxonomy research note 04 adopts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MastMode {
    /// The id the API takes (`step_repetition`).
    pub id: &'static str,
    /// The paper's code (`FM-1.3`).
    pub code: &'static str,
    /// The class: `specification` (system design), `inter_agent_misalignment` or
    /// `task_verification`.
    pub class: &'static str,
    pub name: &'static str,
}

const fn mode(id: &'static str, code: &'static str, class: &'static str, name: &'static str) -> MastMode {
    MastMode { id, code, class, name }
}

/// The 14 MAST failure modes.
pub const MAST: &[MastMode] = &[
    mode("disobey_task_specification", "FM-1.1", "specification", "Disobey task specification"),
    mode("disobey_role_specification", "FM-1.2", "specification", "Disobey role specification"),
    mode("step_repetition", "FM-1.3", "specification", "Step repetition"),
    mode("loss_of_conversation_history", "FM-1.4", "specification", "Loss of conversation history"),
    mode("unaware_of_termination_conditions", "FM-1.5", "specification", "Unaware of termination conditions"),
    mode("conversation_reset", "FM-2.1", "inter_agent_misalignment", "Conversation reset"),
    mode("fail_to_ask_for_clarification", "FM-2.2", "inter_agent_misalignment", "Fail to ask for clarification"),
    mode("task_derailment", "FM-2.3", "inter_agent_misalignment", "Task derailment"),
    mode("information_withholding", "FM-2.4", "inter_agent_misalignment", "Information withholding"),
    mode("ignored_other_agent_input", "FM-2.5", "inter_agent_misalignment", "Ignored other agent's input"),
    mode("reasoning_action_mismatch", "FM-2.6", "inter_agent_misalignment", "Reasoning-action mismatch"),
    mode("premature_termination", "FM-3.1", "task_verification", "Premature termination"),
    mode("no_or_incomplete_verification", "FM-3.2", "task_verification", "No or incomplete verification"),
    mode("incorrect_verification", "FM-3.3", "task_verification", "Incorrect verification"),
];

/// A MAST mode by id.
pub fn mast(id: &str) -> Option<&'static MastMode> {
    MAST.iter().find(|m| m.id == id)
}

/// Most characters in a reviewer's note.
pub const MAX_NOTE: usize = 4000;

/// The judge's bar on captured cases (stricter than the 0.5 default: the reference or the right
/// behaviour is explicit).
pub const THRESHOLD: f64 = 0.7;

/// What a run left that a case is built from (opened with the tenant's data key).
#[derive(Debug, Clone, PartialEq)]
pub struct RunMaterial {
    pub input: Value,
    /// `None` when the run has no output.
    pub output: Option<Value>,
    /// Answers to its human steps (questions and approvals), by step id.
    pub answers: BTreeMap<String, Value>,
    /// The write tools it called, by reference without the pin, in order, once each.
    pub writes: Vec<String>,
}

/// Reads a finished run's material from the journal.
pub async fn material(journal: &Arc<dyn Journal>, sealer: &dyn Sealer, run: &RunRecord) -> Result<RunMaterial, String> {
    let open = |sealed: &str| -> Result<Value, String> {
        let text = sealer.open(&run.tenant_id, &run.id, sealed)?;
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
    };
    let input = open(&run.input)?;
    let output = run.output.as_deref().map(open).transpose()?;
    let steps = journal.steps(&run.id).await.map_err(|e| e.to_string())?;
    let mut answers = BTreeMap::new();
    let mut writes: Vec<String> = Vec::new();
    for s in &steps {
        match s.kind.as_str() {
            "human" | "approval" => {
                let Some(sealed) =
                    journal.event(&run.id, &s.step_id).await.map_err(|e| e.to_string())?.and_then(|e| e.payload)
                else {
                    continue;
                };
                // Stored as {"$answer": ..., "$by": ...} (older answers bare): the answer only,
                // never who gave it.
                let answer = match open(&sealed)? {
                    Value::Object(mut m) if m.contains_key("$answer") => m.remove("$answer").unwrap_or(Value::Null),
                    other => other,
                };
                answers.insert(s.step_id.clone(), answer);
            }
            "tool" => {
                for prefix in [WRITE_EVENT, OBSERVATION] {
                    let name = format!("{prefix}{}", s.step_id);
                    let Some(sealed) =
                        journal.event(&run.id, &name).await.map_err(|e| e.to_string())?.and_then(|e| e.payload)
                    else {
                        continue;
                    };
                    let v = open(&sealed)?;
                    if v["effect"] != "write" {
                        continue;
                    }
                    let reference = v["tool"].as_str().unwrap_or_default();
                    let tool = reference.split_once('#').map_or(reference, |(unpinned, _)| unpinned).to_owned();
                    if !tool.is_empty() && !writes.contains(&tool) {
                        writes.push(tool);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(RunMaterial { input, output, answers, writes })
}

/// What a reviewer said about a run.
#[derive(Debug, Clone, PartialEq)]
pub struct Review<'a> {
    pub verdict: Verdict,
    pub note: Option<&'a str>,
    pub mast: Option<&'static MastMode>,
}

/// Why a run cannot become a case (the control plane answers `409` or `422`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// It has not finished.
    InProgress,
    /// The review or the run does not fit (a `good` run without output, a `bad` one without a
    /// note, a label on a `good` run, an injection-suite run).
    Invalid(String),
}

/// Checks a run and a review before anything is read.
pub fn admissible(run: &RunRecord, review: &Review<'_>) -> Result<(), Refusal> {
    if !run.status.is_terminal() {
        return Err(Refusal::InProgress);
    }
    if run.origin.as_deref().is_some_and(|o| o.starts_with("injection:")) {
        return Err(Refusal::Invalid(
            "an injection-suite run carries an attack in its input: it cannot become a golden case".into(),
        ));
    }
    let note = review.note.map(str::trim).filter(|n| !n.is_empty());
    if review.note.is_some_and(|n| n.chars().count() > MAX_NOTE) {
        return Err(Refusal::Invalid(format!("note: at most {MAX_NOTE} characters")));
    }
    match review.verdict {
        Verdict::Good if run.status != RunStatus::Succeeded => Err(Refusal::Invalid(format!(
            "a run marked good must have succeeded (this one is {}): mark it bad with a note on the right behaviour",
            run.status.as_str()
        ))),
        Verdict::Good if review.mast.is_some() => {
            Err(Refusal::Invalid("mast_label is a failure label: only a run marked bad takes one".into()))
        }
        Verdict::Bad if note.is_none() => Err(Refusal::Invalid(
            "a run marked bad needs a note saying what the right behaviour is (it becomes the judge's rubric)".into(),
        )),
        _ => Ok(()),
    }
}

/// The case id of a run.
pub fn case_id(run_id: &str) -> String {
    // Run ids are `run_<hex>`: already a valid case id (1 to 64 of [A-Za-z0-9_.-]).
    run_id.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')).take(64).collect()
}

/// Builds the case. `output_schema`: the target version's `prompt.output_schema`.
pub fn case_from_run(run_id: &str, m: &RunMaterial, review: &Review<'_>, output_schema: Option<&Value>) -> GoldenCase {
    let note = review.note.map(str::trim).filter(|n| !n.is_empty());
    let mut checks = Vec::new();
    if let Some(s) = output_schema {
        checks.push(Check::JsonSchema { schema: s.clone() });
    }
    match review.verdict {
        Verdict::Good => {
            let mut rubric = "A reviewer marked the reference answer as right for this input. Score 1 when the output \
                              reaches the same decisions, facts and actions as the reference (wording may differ), 0 \
                              when it contradicts it or leaves out what matters."
                .to_owned();
            if let Some(n) = note {
                rubric.push_str(&format!("\nWhat the right behaviour is, in the reviewer's words: {n}"));
            }
            checks.push(Check::LlmJudge { rubric, model: None, threshold: THRESHOLD, reference: m.output.clone() });
            for tool in &m.writes {
                checks.push(Check::ToolCall { tool: tool.clone(), args: None, must_not_call: false });
            }
        }
        Verdict::Bad => {
            let failure = review.mast.map(|f| format!(" ({}, MAST {})", f.name, f.code)).unwrap_or_default();
            let rubric = format!(
                "A reviewer marked an earlier output of this system for this input as wrong{failure}. The right \
                 behaviour, in the reviewer's words: {}\nScore 1 when the output does what the right behaviour says, \
                 0 when it repeats the mistake.",
                note.unwrap_or_default()
            );
            checks.push(Check::LlmJudge { rubric, model: None, threshold: THRESHOLD, reference: None });
        }
    }
    let mut tags = vec!["captured".to_owned(), review.verdict.as_str().to_owned()];
    if let Some(f) = review.mast {
        tags.push(format!("mast:{}", f.id));
    }
    GoldenCase {
        id: case_id(run_id),
        input: m.input.clone(),
        expected: None,
        checks,
        answers: m.answers.clone(),
        tool_results: BTreeMap::new(),
        tags,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn material() -> RunMaterial {
        RunMaterial {
            input: json!({"case": "Refund TX-30015"}),
            output: Some(json!({"status": "refunded"})),
            answers: BTreeMap::from([("clarify#0".to_owned(), json!("two days"))]),
            writes: vec!["mcp://bank/refund".into()],
        }
    }

    #[test]
    fn the_taxonomy_has_fourteen_modes_in_three_classes() {
        assert_eq!(MAST.len(), 14);
        let classes: std::collections::BTreeSet<&str> = MAST.iter().map(|m| m.class).collect();
        assert_eq!(classes.len(), 3);
        assert_eq!(mast("step_repetition").unwrap().code, "FM-1.3");
        assert!(mast("FM-1.3").is_none());
    }

    #[test]
    fn a_good_run_becomes_a_reference_case_with_its_writes() {
        let review = Review { verdict: Verdict::Good, note: None, mast: None };
        let schema = json!({"type": "object", "required": ["status"]});
        let c = case_from_run("run_0a1b", &material(), &review, Some(&schema));
        assert_eq!(c.id, "run_0a1b");
        assert_eq!(c.answers["clarify#0"], "two days");
        assert_eq!(c.checks.iter().map(Check::kind).collect::<Vec<_>>(), ["json_schema", "llm_judge", "tool_call"]);
        assert!(matches!(&c.checks[1], Check::LlmJudge { reference: Some(r), .. } if r["status"] == "refunded"));
        assert!(
            matches!(&c.checks[2], Check::ToolCall { tool, args: None, must_not_call: false } if tool == "mcp://bank/refund")
        );
        assert_eq!(c.tags, ["captured", "good"]);
    }

    #[test]
    fn a_bad_run_becomes_a_rubric_from_the_note() {
        let review = Review {
            verdict: Verdict::Bad,
            note: Some("Ask which transaction first."),
            mast: mast("fail_to_ask_for_clarification"),
        };
        let c = case_from_run("run_1", &material(), &review, None);
        assert_eq!(c.checks.len(), 1, "no schema, no write asserted");
        let Check::LlmJudge { rubric, reference, .. } = &c.checks[0] else { panic!() };
        assert!(rubric.contains("Ask which transaction first.") && rubric.contains("FM-2.2"), "{rubric}");
        assert!(reference.is_none());
        assert_eq!(c.tags, ["captured", "bad", "mast:fail_to_ask_for_clarification"]);
    }
}
