//! Caliban's P0 measurement suite (reference architecture §8: "Under 3 ms p50 overhead.
//! Isolation audit passes. Usage matches provider bills within 1%").
//!
//! - [`mock`]: a deterministic mock upstream (OpenAI Chat Completions and Anthropic Messages,
//!   streaming and not) with fixed latency and deterministic usage.
//! - [`harness`]: runs the real `caliban` binary in `standalone` mode against a generated config.
//! - [`load`]: closed-loop load generator with HDR histograms.
//!
//! Binaries: `mock-upstream` (the mock as its own process) and `caliban-bench` (the overhead
//! benchmark; `scripts/bench.sh` drives it). The isolation audit and the usage-accuracy check
//! are `cargo test` integration tests in `apps/caliban/tests/`.

pub mod harness;
pub mod load;
pub mod mock;
