//! Mock upstream provider as a standalone process (see `caliban_bench::mock`).

use caliban_bench::mock::{Mock, MockConfig};
use clap::Parser;
use std::time::Duration;

#[derive(Parser)]
#[command(about = "Mock OpenAI / Anthropic upstream with fixed latency and deterministic usage")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:18000")]
    addr: String,
    /// Fixed delay before each response (or before the first stream chunk), in milliseconds.
    #[arg(long, default_value_t = 0.0)]
    latency_ms: f64,
    /// Delay between stream chunks, in milliseconds.
    #[arg(long, default_value_t = 0.0)]
    chunk_delay_ms: f64,
    /// Characters per streamed text delta.
    #[arg(long, default_value_t = 4)]
    chunk_chars: usize,
    /// Keep a request log, bills and simulated prompt caches (GET /__mock/log).
    #[arg(long)]
    record: bool,
    /// Cut or pad every reply to this many characters, so its length (and the number of stream
    /// chunks) does not depend on the prompt. Unset: echo the last user message.
    #[arg(long)]
    reply_chars: Option<usize>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let a = Args::parse();
    let cfg = MockConfig {
        latency: Duration::from_secs_f64(a.latency_ms / 1000.0),
        chunk_delay: Duration::from_secs_f64(a.chunk_delay_ms / 1000.0),
        chunk_chars: a.chunk_chars,
        record: a.record,
        reply_chars: a.reply_chars,
        responder: None,
    };
    let mock = Mock::start(&a.addr, cfg).await?;
    println!("mock upstream listening on {}", mock.addr);
    tokio::signal::ctrl_c().await?;
    Ok(())
}
