//! CPU latency + concurrency benchmark for the L1 NER detector.
//!
//! ```sh
//! cargo run --release -p caliban-pii --features ner --example ner_bench -- <artifact-dir>
//! ```
//! Reports ms per 1k tokens (single request) and throughput under concurrent requests for a
//! single mutex-guarded session vs a session pool.

use caliban_pii::{Detector, NerDetector, NerOptions};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

const PARA: &str = "Sarah Johnson from Globex Corporation met Kevin Park in Denver to review the \
quarterly numbers. They agreed that the Chicago office would send the updated forecast to \
Angela Merkel's team by Friday, and that the contract with Initech would be renewed. ";

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).expect("usage: ner_bench <artifact-dir>"));
    let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let mut tok = tokenizers::Tokenizer::from_file(dir.join("tokenizer.json")).unwrap();
    tok.with_truncation(None).unwrap();
    let ntok = |s: &str| tok.encode(s, false).unwrap().len();

    // ~1k-token text.
    let mut text = String::new();
    while ntok(&text) < 1000 {
        text.push_str(PARA);
    }
    let tokens = ntok(&text);
    println!("cores={cores} text={tokens} tokens ({} bytes)", text.len());

    for threads in [1, 2, 4] {
        let d = NerDetector::load(&dir, NerOptions { intra_threads: threads, ..NerOptions::default() }).unwrap();
        let _ = d.try_detect(&text).unwrap(); // warm-up
        // Median of 15: robust against other load on the machine.
        let mut runs = Vec::new();
        let mut n = 0;
        for _ in 0..15 {
            let t = Instant::now();
            n = d.try_detect(&text).unwrap().len();
            runs.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        runs.sort_by(f64::total_cmp);
        let ms = runs[runs.len() / 2];
        println!(
            "intra_threads={threads}: {ms:.1} ms per request = {:.1} ms / 1k tokens ({n} spans)",
            ms * 1000.0 / tokens as f64
        );
    }
    // Short prompt latency (typical chat turn).
    let short = "Please email Sarah Johnson at Globex about the Denver offsite.";
    let d = NerDetector::load(&dir, NerOptions { intra_threads: 2, ..NerOptions::default() }).unwrap();
    let _ = d.try_detect(short);
    let mut runs: Vec<f64> = (0..51)
        .map(|_| {
            let t = Instant::now();
            d.try_detect(short).unwrap();
            t.elapsed().as_secs_f64() * 1000.0
        })
        .collect();
    runs.sort_by(f64::total_cmp);
    println!("short prompt ({} tokens): median {:.2} ms", ntok(short), runs[25]);

    // Concurrency: 8 client threads × 5 requests of ~1k tokens.
    let clients = 8;
    let per = 5;
    for (sessions, intra) in [(1, cores.min(4)), (2, (cores / 2).clamp(1, 4)), (4, (cores / 4).max(1))] {
        let d = Arc::new(NerDetector::load(&dir, NerOptions { sessions, intra_threads: intra, ..NerOptions::default() }).unwrap());
        let _ = d.try_detect(&text);
        let t = Instant::now();
        let hs: Vec<_> = (0..clients)
            .map(|_| {
                let d = Arc::clone(&d);
                let text = text.clone();
                std::thread::spawn(move || {
                    for _ in 0..per {
                        d.try_detect(&text).unwrap();
                    }
                })
            })
            .collect();
        hs.into_iter().for_each(|h| h.join().unwrap());
        let secs = t.elapsed().as_secs_f64();
        let reqs = (clients * per) as f64;
        println!(
            "sessions={sessions} intra_threads={intra}: {:.1} req/s, {:.0} k tokens/s, mean wall/request {:.0} ms",
            reqs / secs,
            reqs * tokens as f64 / secs / 1000.0,
            secs * 1000.0 / per as f64
        );
    }
}
