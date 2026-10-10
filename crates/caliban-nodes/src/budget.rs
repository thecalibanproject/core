//! Hierarchical budget ledger: tenant → node → run → subnode. A child can only spend what its
//! parent has left; overruns stop the run with partial results instead of failing silently.
//!
//! Dimensions:
//! - **steps** and **tokens**: spent by every step (tokens: prompt plus completion of model calls);
//! - **USD**: spent by model calls, priced as the metering prices them (the flat `caliban/auto`
//!   price with its cache-hit discount, or the pinned model's price);
//! - **wall clock**: execution time of the run (not time waiting for a human or a timer); a child
//!   gets a deadline no later than its parent's;
//! - **depth**: nesting levels left below this ledger (a subnode or `node://` tool takes one);
//! - **fan-out**: the most branches a `map` may run at once under this ledger.
//!
//! Steps, tokens and USD are consumed on this ledger and on every ancestor; depth, fan-out and the
//! deadline are caps a child inherits (it gets at most what its parent has).
//!
//! The executor persists the run's spend ([`BudgetState`]) with every checkpoint, and a resumed run
//! rebuilds its ledger by replaying the recorded steps (their tokens and USD are charged again),
//! so it keeps what it already spent. Tenant-wide caps (daily, monthly) sit above the run: the
//! executor checks them against the journal before every model call (see `executor`).

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Limits (or what is left) of a ledger. `usd` is `f64::INFINITY` when there is no USD cap.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Budget {
    pub steps: u32,
    pub tokens: u64,
    pub usd: f64,
    /// Execution time in milliseconds.
    pub wall_clock_ms: u64,
    /// Nesting levels allowed below.
    pub depth: u32,
    /// Concurrent `map` branches allowed.
    pub fanout: u32,
}

impl Budget {
    /// Steps and tokens only (tests and simple callers): no USD cap, no wall clock, depth and
    /// fan-out at their spec defaults.
    pub fn simple(steps: u32, tokens: u64) -> Self {
        Self { steps, tokens, usd: f64::INFINITY, wall_clock_ms: u64::MAX, depth: 3, fanout: 8 }
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum BudgetError {
    #[error("step budget exhausted")]
    Steps,
    #[error("token budget exhausted (requested {requested}, left {left})")]
    Tokens { requested: u64, left: u64 },
    #[error("USD budget exhausted (${spent:.6} spent of ${limit:.6})")]
    Usd { spent: f64, limit: f64 },
    #[error("wall-clock budget exhausted ({used_ms} ms of {limit_ms} ms)")]
    WallClock { used_ms: u64, limit_ms: u64 },
    #[error("depth budget exhausted (nesting deeper than {limit} levels)")]
    Depth { limit: u32 },
}

#[derive(Debug)]
struct Inner {
    limit: Budget,
    left: Budget,
    /// Run-elapsed millisecond at which this ledger's wall clock runs out.
    deadline_ms: u64,
    parent: Option<Ledger>,
}

#[derive(Debug, Clone)]
pub struct Ledger(Arc<Mutex<Inner>>);

impl Ledger {
    /// The run's ledger. Its wall clock is measured in run-elapsed milliseconds from 0.
    pub fn root(budget: Budget) -> Self {
        Self(Arc::new(Mutex::new(Inner {
            limit: budget,
            left: budget,
            deadline_ms: budget.wall_clock_ms,
            parent: None,
        })))
    }

    /// Child ledger capped by both `cap` and what the parent has left. `now_ms` is the run's
    /// elapsed time (the child's wall clock starts now). Fails when the parent has no nesting
    /// level left.
    pub fn child(&self, cap: Budget, now_ms: u64) -> Result<Self, BudgetError> {
        let (parent_left, parent_deadline) = {
            let g = self.0.lock();
            (g.left, g.deadline_ms)
        };
        if parent_left.depth == 0 {
            return Err(BudgetError::Depth { limit: self.root_limit().depth });
        }
        let deadline_ms = parent_deadline.min(now_ms.saturating_add(cap.wall_clock_ms));
        let left = Budget {
            steps: cap.steps.min(parent_left.steps),
            tokens: cap.tokens.min(parent_left.tokens),
            usd: cap.usd.min(parent_left.usd),
            wall_clock_ms: deadline_ms.saturating_sub(now_ms),
            depth: cap.depth.min(parent_left.depth - 1),
            fanout: cap.fanout.min(parent_left.fanout),
        };
        Ok(Self(Arc::new(Mutex::new(Inner { limit: left, left, deadline_ms, parent: Some(self.clone()) }))))
    }

    fn root_limit(&self) -> Budget {
        let mut cur = self.clone();
        loop {
            let next = cur.0.lock().parent.clone();
            match next {
                Some(p) => cur = p,
                None => return cur.limit(),
            }
        }
    }

    pub fn remaining(&self) -> Budget {
        self.0.lock().left
    }

    /// What this ledger was created with (a child: capped by its parent at creation).
    pub fn limit(&self) -> Budget {
        self.0.lock().limit
    }

    /// How many levels below the run this ledger is (the run's own ledger: 0).
    pub fn level(&self) -> u32 {
        let mut n = 0;
        let mut cur = self.0.lock().parent.clone();
        while let Some(p) = cur {
            n += 1;
            cur = p.0.lock().parent.clone();
        }
        n
    }

    /// Charges one step and `tokens` here and on every ancestor, atomically per level.
    pub fn charge(&self, tokens: u64) -> Result<(), BudgetError> {
        self.check(tokens, 0.0)?;
        self.record(tokens, 0.0);
        Ok(())
    }

    /// Before a step: is there a step, a token and some USD left here and on every ancestor?
    pub fn ensure_step(&self) -> Result<(), BudgetError> {
        self.check(1, 0.0)
    }

    /// Before a step: its wall clock, here and on every ancestor (`elapsed_ms`: the run's).
    pub fn ensure_time(&self, elapsed_ms: u64) -> Result<(), BudgetError> {
        let mut cur = Some(self.clone());
        while let Some(l) = cur {
            let g = l.0.lock();
            if elapsed_ms >= g.deadline_ms {
                let start = g.deadline_ms.saturating_sub(g.limit.wall_clock_ms);
                return Err(BudgetError::WallClock {
                    used_ms: elapsed_ms.saturating_sub(start),
                    limit_ms: g.limit.wall_clock_ms,
                });
            }
            cur = g.parent.clone();
        }
        Ok(())
    }

    /// After a step whose cost is only known now (a model call): records one step, `tokens` and
    /// `usd` whatever is left (spend that already happened is never lost), and reports an overrun.
    pub fn charge_spent(&self, tokens: u64, usd: f64) -> Result<(), BudgetError> {
        let over = self.check(tokens, usd);
        self.record(tokens, usd);
        over
    }

    /// The most `map` branches allowed at once here (the tightest cap of this ledger's chain).
    pub fn fanout(&self) -> u32 {
        self.0.lock().left.fanout
    }

    fn record(&self, tokens: u64, usd: f64) {
        let mut cur = Some(self.clone());
        while let Some(l) = cur {
            let mut g = l.0.lock();
            g.left.steps = g.left.steps.saturating_sub(1);
            g.left.tokens = g.left.tokens.saturating_sub(tokens);
            g.left.usd -= usd;
            cur = g.parent.clone();
        }
    }

    fn check(&self, tokens: u64, usd: f64) -> Result<(), BudgetError> {
        let mut cur = Some(self.clone());
        while let Some(l) = cur {
            let g = l.0.lock();
            if g.left.steps == 0 {
                return Err(BudgetError::Steps);
            }
            if g.left.tokens < tokens {
                return Err(BudgetError::Tokens { requested: tokens, left: g.left.tokens });
            }
            // No USD left (or this cost overruns it). An unlimited ledger never trips.
            if g.limit.usd.is_finite() && (g.left.usd <= 0.0 || usd > g.left.usd + 1e-12) {
                return Err(BudgetError::Usd { spent: g.limit.usd - g.left.usd + usd, limit: g.limit.usd });
            }
            cur = g.parent.clone();
        }
        Ok(())
    }
}

/// A run's budget as persisted in the journal (`node_run.budget`): limits and spend. Fields added
/// after the first release default when absent, so older rows still parse.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct BudgetState {
    pub steps_limit: u32,
    pub steps_used: u32,
    pub tokens_limit: u64,
    pub tokens_used: u64,
    pub wall_clock_ms_limit: u64,
    /// Time spent executing (not waiting for a human or a timer), across workers.
    pub wall_clock_ms_used: u64,
    /// Model spend of the run, priced like the metering prices it.
    pub usd: f64,
    /// USD cap of the run (`None`: no run-level cap; tenant caps still apply).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usd_limit: Option<f64>,
    /// Nesting levels allowed below the run, and the deepest level the run reached.
    #[serde(default)]
    pub depth_limit: u32,
    #[serde(default)]
    pub depth_used: u32,
    /// Concurrent `map` branches allowed, and the most the run ran at once.
    #[serde(default)]
    pub fanout_limit: u32,
    #[serde(default)]
    pub fanout_used: u32,
}

impl BudgetState {
    pub fn new(steps: u32, tokens: u64, wall_clock_s: u64) -> Self {
        Self {
            steps_limit: steps,
            tokens_limit: tokens,
            wall_clock_ms_limit: wall_clock_s.saturating_mul(1000),
            depth_limit: 3,
            fanout_limit: 8,
            ..Self::default()
        }
    }

    /// The root ledger's limits (old rows without depth or fan-out get the spec defaults).
    pub fn ledger_limits(&self) -> Budget {
        Budget {
            steps: self.steps_limit,
            tokens: self.tokens_limit,
            usd: self.usd_limit.unwrap_or(f64::INFINITY),
            wall_clock_ms: if self.wall_clock_ms_limit == 0 { u64::MAX } else { self.wall_clock_ms_limit },
            depth: if self.depth_limit == 0 && self.fanout_limit == 0 { 3 } else { self.depth_limit },
            fanout: if self.fanout_limit == 0 { 8 } else { self.fanout_limit },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_spend_counts_against_parent() {
        let root = Ledger::root(Budget::simple(10, 1000));
        let child = root.child(Budget::simple(5, 5000), 0).unwrap();
        assert_eq!(child.remaining().tokens, 1000, "capped by parent");
        child.charge(600).unwrap();
        assert_eq!((root.remaining().steps, root.remaining().tokens), (9, 400));
        assert_eq!(child.charge(500), Err(BudgetError::Tokens { requested: 500, left: 400 }));
    }

    #[test]
    fn steps_run_out() {
        let l = Ledger::root(Budget::simple(1, 10));
        l.charge(1).unwrap();
        assert_eq!(l.charge(1), Err(BudgetError::Steps));
    }

    #[test]
    fn spent_tokens_are_recorded_even_past_the_limit() {
        let l = Ledger::root(Budget::simple(5, 100));
        l.ensure_step().unwrap();
        assert_eq!(l.charge_spent(150, 0.0), Err(BudgetError::Tokens { requested: 150, left: 100 }));
        assert_eq!((l.remaining().steps, l.remaining().tokens), (4, 0));
        assert_eq!(l.ensure_step(), Err(BudgetError::Tokens { requested: 1, left: 0 }));
        assert_eq!(l.limit(), Budget::simple(5, 100));
    }

    #[test]
    fn usd_is_capped_and_a_child_gets_what_its_parent_has_left() {
        let root = Ledger::root(Budget { usd: 0.01, ..Budget::simple(100, 100_000) });
        root.charge_spent(10, 0.004).unwrap();
        let child = root.child(Budget { usd: 1.0, ..Budget::simple(100, 100_000) }, 0).unwrap();
        assert!((child.remaining().usd - 0.006).abs() < 1e-12, "{:?}", child.remaining());
        child.charge_spent(10, 0.005).unwrap();
        // The next call overruns: recorded anyway, and reported.
        assert!(matches!(child.charge_spent(10, 0.002), Err(BudgetError::Usd { .. })));
        assert!(matches!(root.ensure_step(), Err(BudgetError::Usd { .. })), "the parent is spent too");
        // No USD cap: never trips.
        let free = Ledger::root(Budget::simple(10, 100));
        free.charge_spent(1, 1e9).unwrap();
        free.ensure_step().unwrap();
    }

    #[test]
    fn depth_fanout_and_deadlines_are_inherited() {
        let root = Ledger::root(Budget { depth: 1, fanout: 4, wall_clock_ms: 1000, ..Budget::simple(10, 100) });
        let child =
            root.child(Budget { depth: 5, fanout: 16, wall_clock_ms: 10_000, ..Budget::simple(10, 100) }, 400).unwrap();
        assert_eq!((child.remaining().depth, child.fanout(), child.level()), (0, 4, 1));
        assert!(matches!(child.child(Budget::simple(1, 1), 400), Err(BudgetError::Depth { .. })));
        // The child's deadline is the parent's (1000 ms), not 400 + 10 s.
        child.ensure_time(999).unwrap();
        assert!(matches!(child.ensure_time(1000), Err(BudgetError::WallClock { .. })));
        let short = root.child(Budget { wall_clock_ms: 100, ..Budget::simple(10, 100) }, 400).unwrap();
        assert!(matches!(short.ensure_time(500), Err(BudgetError::WallClock { used_ms: 100, limit_ms: 100 })));
        root.ensure_time(500).unwrap();
    }

    #[test]
    fn old_rows_get_default_depth_and_fanout() {
        let old: BudgetState = serde_json::from_str(
            r#"{"steps_limit":5,"steps_used":0,"tokens_limit":10,"tokens_used":0,"wall_clock_ms_limit":1000,"wall_clock_ms_used":0,"usd":0.0}"#,
        )
        .unwrap();
        let b = old.ledger_limits();
        assert_eq!((b.depth, b.fanout, b.usd.is_infinite()), (3, 8, true));
    }
}
