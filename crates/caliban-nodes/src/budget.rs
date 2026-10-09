//! Hierarchical budget ledger: tenant → node → run → subnode. A child can only spend what its
//! parent has left; overruns stop the run with partial results instead of failing silently.

use parking_lot::Mutex;
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
}

#[derive(Debug)]
struct Inner {
    left: Budget,
    parent: Option<Ledger>,
}

#[derive(Debug, Clone)]
pub struct Ledger(Arc<Mutex<Inner>>);

impl Ledger {
    pub fn root(budget: Budget) -> Self {
        Self(Arc::new(Mutex::new(Inner { left: budget, parent: None })))
    }

    /// Child ledger capped by both `cap` and what the parent has left.
    pub fn child(&self, cap: Budget) -> Self {
        let parent_left = self.remaining();
        let left = Budget { steps: cap.steps.min(parent_left.steps), tokens: cap.tokens.min(parent_left.tokens) };
        Self(Arc::new(Mutex::new(Inner { left, parent: Some(self.clone()) })))
    }

    pub fn remaining(&self) -> Budget {
        self.0.lock().left
    }

    /// Charges one step and `tokens` here and on every ancestor, atomically per level.
    pub fn charge(&self, tokens: u64) -> Result<(), BudgetError> {
        self.check(tokens)?;
        let mut cur = Some(self.clone());
        while let Some(l) = cur {
            let mut g = l.0.lock();
            g.left.steps = g.left.steps.saturating_sub(1);
            g.left.tokens = g.left.tokens.saturating_sub(tokens);
            cur = g.parent.clone();
        }
        Ok(())
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
}
