//! The semantic-cache guards over the AWS runs' hand-written pairs (`bench/scripts/semcache_pairs.py`:
//! 36 paraphrases that should hit and 38 near-misses that must not). Guard only, no embedder: a
//! paraphrase "passes" when both prompts have the same [`Signature`] (the embedding threshold then
//! decides); a near-miss is "blocked" when they differ (it can never hit, whatever the threshold).
//!
//! `cargo test -p caliban-cache --test guard_pairs -- --nocapture` prints every verdict.

use caliban_cache::semantic::signature;

/// The double-quoted Python string literals of one line, in order.
fn strings(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (&mut cur, c) {
            (None, '"') => cur = Some(String::new()),
            (None, '#') => break,
            (Some(s), '\\') => {
                if let Some(n) = chars.next() {
                    s.push(n);
                }
            }
            (Some(_), '"') => out.extend(cur.take()),
            (Some(s), c) => s.push(c),
            _ => {}
        }
    }
    out
}

fn pairs(list: &str) -> Vec<(String, String)> {
    let src = include_str!("../../../bench/scripts/semcache_pairs.py");
    let start = src.find(&format!("{list} = [")).expect("list in semcache_pairs.py");
    let body = &src[start..];
    let body = &body[..body.find("\n]").expect("end of list")];
    body.lines()
        .filter_map(|l| match strings(l).as_slice() {
            [a, b] => Some((a.clone(), b.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn guard_verdicts_over_the_bench_pairs() {
    let para = pairs("PARAPHRASES");
    let near = pairs("NEAR_MISSES");
    assert_eq!((para.len(), near.len()), (36, 38), "the pair sets changed");

    let mut passing = Vec::new();
    for (a, b) in &para {
        let ok = signature(a) == signature(b);
        println!("paraphrase {} {a:?} / {b:?}", if ok { "PASS " } else { "BLOCK" });
        if ok {
            passing.push(a.as_str());
        } else {
            println!("    {:?}\n    {:?}", signature(a), signature(b));
        }
    }
    let mut blocked = 0;
    for (a, b) in &near {
        let ok = signature(a) == signature(b);
        println!("near-miss  {} {a:?} / {b:?}", if ok { "PASS " } else { "BLOCK" });
        blocked += usize::from(!ok);
    }
    println!(
        "guard only: {} of {} paraphrases comparable, {blocked} of {} near-misses blocked",
        passing.len(),
        para.len(),
        near.len()
    );
    // The three paraphrases the guards cost in the second AWS run (bench/RESULTS-aws-2026-10b.md).
    for a in [
        "What is the VAT rate in Germany?",
        "Who approves expense reports over 5000 EUR?",
        "How do I format a date as YYYY-MM-DD in JavaScript?",
    ] {
        assert!(passing.contains(&a), "{a:?} is still blocked by the guards");
    }
    // Measured on this set before and after loosening the guards (possessives, inflections of
    // approve and reject, format specs): 29 -> 33 paraphrases comparable, 24 near-misses blocked
    // both times. The rest of the near-misses are left to the threshold, which kept all 38 out
    // in the AWS run.
    assert!(passing.len() >= 33, "{} paraphrases comparable", passing.len());
    assert!(blocked >= 24, "{blocked} near-misses blocked");
}
