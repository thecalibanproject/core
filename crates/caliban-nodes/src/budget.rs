//! Hierarchical budget ledger: tenant → node → run → subnode. A child can only spend what its
//! parent has left; overruns stop the run with partial results instead of failing silently.
//!
//! The executor persists the run's spend ([`BudgetState`]) with every checkpoint, and a resumed run
//! rebuilds its ledger by replaying the recorded steps, so it keeps what it already spent.
//!
//! TODO(P3 M3): USD, depth and fan-out as ledger dimensions; tenant (daily, monthly) and node spend
//! caps above the run. USD is recorded in [`BudgetState::usd`] but not capped yet.

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub steps: u32,
    pub tokens: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BudgetError {
    #[error("step budget exhausted")]
    Steps,
    #[error("token budget exhausted (requested {requested}, left {left})")]
    Tokens { requested: u64, left: u64 },
    #[error("wall-clock budget exhausted ({used_ms} ms of {limit_ms} ms)")]
    WallClock { used_ms: u64, limit_ms: u64 },
}

#[derive(Debug)]
struct Inner {
    limit: Budget,
    left: Budget,
    parent: Option<Ledger>,
}

#[derive(Debug, Clone)]
pub struct Ledger(Arc<Mutex<Inner>>);

impl Ledger {
    pub fn root(budget: Budget) -> Self {
        Self(Arc::new(Mutex::new(Inner { limit: budget, left: budget, parent: None })))
    }

    /// Child ledger capped by both `cap` and what the parent has left.
    pub fn child(&self, cap: Budget) -> Self {
        let parent_left = self.remaining();
        let left = Budget { steps: cap.steps.min(parent_left.steps), tokens: cap.tokens.min(parent_left.tokens) };
        Self(Arc::new(Mutex::new(Inner { limit: left, left, parent: Some(self.clone()) })))
    }

    pub fn remaining(&self) -> Budget {
        self.0.lock().left
    }

    /// What this ledger was created with (a child: capped by its parent at creation).
    pub fn limit(&self) -> Budget {
        self.0.lock().limit
    }

    /// Charges one step and `tokens` here and on every ancestor, atomically per level.
    pub fn charge(&self, tokens: u64) -> Result<(), BudgetError> {
        self.check(tokens)?;
        self.record(tokens);
        Ok(())
    }

    /// Before a step: is there a step and at least one token left here and on every ancestor?
    pub fn ensure_step(&self) -> Result<(), BudgetError> {
        self.check(1)
    }

    /// After a step whose cost is only known now (a model call): records one step and `tokens`
    /// whatever is left (spend that already happened is never lost), and reports an overrun.
    pub fn charge_spent(&self, tokens: u64) -> Result<(), BudgetError> {
        let over = self.check(tokens);
        self.record(tokens);
        over
    }

    fn record(&self, tokens: u64) {
        let mut cur = Some(self.clone());
        while let Some(l) = cur {
            let mut g = l.0.lock();
            g.left.steps = g.left.steps.saturating_sub(1);
            g.left.tokens = g.left.tokens.saturating_sub(tokens);
            cur = g.parent.clone();
        }
    }

    fn check(&self, tokens: u64) -> Result<(), BudgetError> {
        let mut cur = Some(self.clone());
        while let Some(l) = cur {
            let g = l.0.lock();
            if g.left.steps == 0 {
                return Err(BudgetError::Steps);
            }
            if g.left.tokens < tokens {
                return Err(BudgetError::Tokens { requested: tokens, left: g.left.tokens });
            }
            cur = g.parent.clone();
        }
        Ok(())
    }
}

/// A run's budget as persisted in the journal (`node_run.budget`): limits and spend.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct BudgetState {
    pub steps_limit: u32,
    pub steps_used: u32,
    pub tokens_limit: u64,
    pub tokens_used: u64,
    pub wall_clock_ms_limit: u64,
    /// Time spent executing (not waiting for a human or a timer), across workers.
    pub wall_clock_ms_used: u64,
    /// Model spend of the run (recorded, not capped until P3 M3).
    pub usd: f64,
}

impl BudgetState {
    pub fn new(steps: u32, tokens: u64, wall_clock_s: u64) -> Self {
        Self {
            steps_limit: steps,
            tokens_limit: tokens,
            wall_clock_ms_limit: wall_clock_s.saturating_mul(1000),
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_spend_counts_against_parent() {
        let root = Ledger::root(Budget { steps: 10, tokens: 1000 });
        let child = root.child(Budget { steps: 5, tokens: 5000 });
        assert_eq!(child.remaining().tokens, 1000, "capped by parent");
        child.charge(600).unwrap();
        assert_eq!(root.remaining(), Budget { steps: 9, tokens: 400 });
        assert_eq!(child.charge(500), Err(BudgetError::Tokens { requested: 500, left: 400 }));
    }

    #[test]
    fn steps_run_out() {
        let l = Ledger::root(Budget { steps: 1, tokens: 10 });
        l.charge(1).unwrap();
        assert_eq!(l.charge(1), Err(BudgetError::Steps));
    }

    #[test]
    fn spent_tokens_are_recorded_even_past_the_limit() {
        let l = Ledger::root(Budget { steps: 5, tokens: 100 });
        l.ensure_step().unwrap();
        assert_eq!(l.charge_spent(150), Err(BudgetError::Tokens { requested: 150, left: 100 }));
        assert_eq!(l.remaining(), Budget { steps: 4, tokens: 0 });
        assert_eq!(l.ensure_step(), Err(BudgetError::Tokens { requested: 1, left: 0 }));
        assert_eq!(l.limit(), Budget { steps: 5, tokens: 100 });
    }
}
