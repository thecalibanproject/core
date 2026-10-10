//! Circuit breakers per (tenant, tool), in each worker process.
//!
//! A tool whose calls fail `failures` times in a row (after their retries) **opens** its breaker:
//! calls are refused at once, without reaching the tool, for `cooldown`. Then the breaker is
//! **half-open**: one trial call goes through; success closes it, failure opens it again for
//! another cooldown. Breakers are per process: each worker learns a tool's health on its own,
//! which is enough to stop a run (and the runs after it) from hammering a dead server.

use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug, Clone, Default)]
pub struct Breaker {
    consecutive_failures: u32,
    opened_at: Option<Instant>,
    /// A half-open trial call is in flight.
    trial: bool,
}

/// The breaker key of a tool reference: without its pin (a re-approved manifest is the same tool).
pub fn tool_key(reference: &str) -> String {
    reference.split('#').next().unwrap_or(reference).to_owned()
}

impl Breaker {
    pub fn state(&self, now: Instant, cooldown: Duration) -> State {
        match self.opened_at {
            None => State::Closed,
            Some(at) if now.duration_since(at) < cooldown => State::Open,
            Some(_) => State::HalfOpen,
        }
    }

    /// May a call go through now? `Err` is how long until the next trial.
    pub fn admit(&mut self, now: Instant, cooldown: Duration) -> Result<(), Duration> {
        match self.state(now, cooldown) {
            State::Closed => Ok(()),
            State::Open => Err(cooldown.saturating_sub(now.duration_since(self.opened_at.unwrap_or(now)))),
            State::HalfOpen if self.trial => Err(Duration::ZERO),
            State::HalfOpen => {
                self.trial = true;
                Ok(())
            }
        }
    }

    pub fn record(&mut self, ok: bool, now: Instant, failures: u32) {
        self.trial = false;
        if ok {
            *self = Breaker::default();
            return;
        }
        self.consecutive_failures += 1;
        if self.opened_at.is_some() || self.consecutive_failures >= failures.max(1) {
            self.opened_at = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opens_after_consecutive_failures_and_recovers_after_a_cooldown() {
        let cool = Duration::from_secs(30);
        let t0 = Instant::now();
        let mut b = Breaker::default();
        b.record(false, t0, 3);
        b.record(true, t0, 3);
        b.record(false, t0, 3);
        b.record(false, t0, 3);
        assert_eq!(b.state(t0, cool), State::Closed, "a success resets the count");
        b.record(false, t0, 3);
        assert_eq!(b.state(t0, cool), State::Open);
        assert_eq!(b.admit(t0 + Duration::from_secs(10), cool), Err(Duration::from_secs(20)));
        // Half-open: one trial at a time.
        let later = t0 + cool;
        assert_eq!(b.state(later, cool), State::HalfOpen);
        assert_eq!(b.admit(later, cool), Ok(()));
        assert!(b.admit(later, cool).is_err(), "a second call waits for the trial");
        // The trial fails: open for another cooldown.
        b.record(false, later, 3);
        assert_eq!(b.state(later + Duration::from_secs(1), cool), State::Open);
        // The next trial succeeds: closed.
        let again = later + cool;
        assert_eq!(b.admit(again, cool), Ok(()));
        b.record(true, again, 3);
        assert_eq!(b.state(again, cool), State::Closed);
        assert_eq!(tool_key("mcp://erp/lookup#sha256:ab"), "mcp://erp/lookup");
    }
}
