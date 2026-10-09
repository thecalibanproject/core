//! Chooses where a compiled query runs (docs/research/08-ontology-deep-dive-nosql.md,
//! "Backend planning"): the native MongoDB lane or the CDC-fed replica (DataFusion).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// Aggregation pipeline on a read-only, time-boxed secondary.
    Native,
    /// SQL over the change-stream-fed Parquet replica.
    Replica,
}

/// Summary of a `queryPlanner` explain of the native candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExplainSummary {
    pub uses_index: bool,
    /// Estimated documents examined, when the plan exposes it.
    pub docs_examined: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PlanInputs {
    /// From CQIR `freshness` (seconds); `None` = any freshness is fine.
    pub freshness_slo_secs: Option<u64>,
    /// Current replica lag; `None` = no healthy replica for these entities.
    pub replica_lag_secs: Option<u64>,
    /// Entity bindings allow replication (`replicate != forbidden`).
    pub replication_allowed: bool,
    /// Query spans more than one datasource (only the federated engine can join them).
    pub cross_source: bool,
    pub explain: Option<ExplainSummary>,
    /// Max documents the native lane may examine (default 1M; tune with design partners).
    pub native_budget: u64,
}

impl Default for PlanInputs {
    fn default() -> Self {
        Self {
            freshness_slo_secs: None,
            replica_lag_secs: None,
            replication_allowed: true,
            cross_source: false,
            explain: None,
            native_budget: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub lane: Lane,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlanError {
    #[error("cross-source query needs the replica, but replication is not available or not allowed")]
    CrossSourceWithoutReplica,
    #[error("query is too expensive for the native lane and no replica is available")]
    TooExpensive,
}

pub fn choose(i: &PlanInputs) -> Result<Decision, PlanError> {
    let replica_ok = i.replication_allowed && i.replica_lag_secs.is_some();
    if i.cross_source {
        return if replica_ok {
            Ok(Decision { lane: Lane::Replica, reason: "cross-source join" })
        } else {
            Err(PlanError::CrossSourceWithoutReplica)
        };
    }
    let cheap_native = i.explain.is_some_and(|e| e.uses_index && e.docs_examined.is_none_or(|d| d <= i.native_budget));
    if !replica_ok {
        // With no replica, still refuse plans that explain() shows to be full scans.
        return match i.explain {
            Some(e) if !e.uses_index && e.docs_examined.is_some_and(|d| d > i.native_budget) => Err(PlanError::TooExpensive),
            _ => Ok(Decision { lane: Lane::Native, reason: "no replica" }),
        };
    }
    if let (Some(slo), Some(lag)) = (i.freshness_slo_secs, i.replica_lag_secs)
        && lag > slo {
            return Ok(Decision { lane: Lane::Native, reason: "replica lag exceeds freshness SLO" });
        }
    if cheap_native {
        Ok(Decision { lane: Lane::Native, reason: "indexed and within native budget" })
    } else {
        Ok(Decision { lane: Lane::Replica, reason: "scan-heavy; replica is fresh enough" })
    }
}

/// Parses the small ISO-8601 duration subset CQIR uses (`PT15M`, `PT1H30M`, `P1D`, `PT45S`).
pub fn parse_duration_secs(s: &str) -> Option<u64> {
    let rest = s.strip_prefix('P')?;
    let (date, time) = rest.split_once('T').unwrap_or((rest, ""));
    let mut total = 0u64;
    for (part, units) in [(date, &[('D', 86_400u64)][..]), (time, &[('H', 3600), ('M', 60), ('S', 1)][..])] {
        let mut num = String::new();
        for c in part.chars() {
            if c.is_ascii_digit() {
                num.push(c);
            } else {
                let mult = units.iter().find(|(u, _)| *u == c)?.1;
                total += num.parse::<u64>().ok()? * mult;
                num.clear();
            }
        }
        if !num.is_empty() {
            return None;
        }
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> PlanInputs {
        PlanInputs { replica_lag_secs: Some(30), ..PlanInputs::default() }
    }

    #[test]
    fn indexed_selective_queries_stay_native() {
        let i = PlanInputs { explain: Some(ExplainSummary { uses_index: true, docs_examined: Some(5_000) }), ..base() };
        assert_eq!(choose(&i).unwrap().lane, Lane::Native);
    }

    #[test]
    fn scans_go_to_a_fresh_replica() {
        let i = PlanInputs { explain: Some(ExplainSummary { uses_index: false, docs_examined: Some(9_000_000) }), ..base() };
        assert_eq!(choose(&i).unwrap().lane, Lane::Replica);
    }

    #[test]
    fn freshness_beats_cost() {
        let i = PlanInputs {
            freshness_slo_secs: Some(10),
            explain: Some(ExplainSummary { uses_index: false, docs_examined: Some(9_000_000) }),
            ..base()
        };
        assert_eq!(choose(&i).unwrap().reason, "replica lag exceeds freshness SLO");
    }

    #[test]
    fn forbidden_replication_and_cross_source() {
        let i = PlanInputs { replication_allowed: false, cross_source: true, ..base() };
        assert_eq!(choose(&i), Err(PlanError::CrossSourceWithoutReplica));
        let i = PlanInputs {
            replication_allowed: false,
            explain: Some(ExplainSummary { uses_index: false, docs_examined: Some(9_000_000) }),
            ..base()
        };
        assert_eq!(choose(&i), Err(PlanError::TooExpensive));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration_secs("PT15M"), Some(900));
        assert_eq!(parse_duration_secs("P1DT1H"), Some(90_000));
        assert_eq!(parse_duration_secs("PT45S"), Some(45));
        assert_eq!(parse_duration_secs("15m"), None);
    }
}
