//! Offline eval hook: leave-one-out kNN accuracy of an exemplar set under a real embedder.
//!
//! Skipped unless `CALIBAN_KNN_EVAL_URL` is set. Any OpenAI-compatible `/embeddings` endpoint works
//! (TEI, vLLM, Infinity, llama.cpp, Ollama, a hosted API):
//!
//! ```text
//! CALIBAN_KNN_EVAL_URL=http://localhost:8081/v1 \
//! CALIBAN_KNN_EVAL_MODEL=BAAI/bge-small-en-v1.5 \
//! cargo test -p caliban-route --test knn_eval -- --nocapture
//! ```
//!
//! Optional: `CALIBAN_KNN_EVAL_API_KEY`, `CALIBAN_KNN_EVAL_PREFIX` (e.g. `"query: "` for E5),
//! `CALIBAN_KNN_EVAL_DATASET` (ml intent dataset, JSON; default: the built-in set),
//! `CALIBAN_KNN_EVAL_K`, `CALIBAN_KNN_EVAL_TEMPERATURE`, `CALIBAN_KNN_EVAL_MIN_ACCURACY` (fails the
//! test below it). The report also prints the top-1 similarity of the dataset's `oos` examples, as a
//! starting point for `[routing] oos_threshold`; proper calibration is ml's `caliban-ml router knn-eval`.

use caliban_route::exemplars::IntentDataset;
use caliban_route::knn::{KnnIndex, KnnParams};
use serde_json::{Value, json};

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

async fn embed(client: &reqwest::Client, url: &str, model: &str, key: Option<&str>, texts: &[String]) -> Vec<Vec<f32>> {
    let mut out = Vec::with_capacity(texts.len());
    for batch in texts.chunks(32) {
        let mut rq = client
            .post(format!("{}/embeddings", url.trim_end_matches('/')))
            .json(&json!({"model": model, "input": batch}));
        if let Some(k) = key {
            rq = rq.bearer_auth(k);
        }
        let v: Value = rq
            .send()
            .await
            .expect("embedding request")
            .error_for_status()
            .expect("embedding status")
            .json()
            .await
            .expect("embedding json");
        let mut data: Vec<(u64, Vec<f32>)> = v["data"]
            .as_array()
            .expect("data array")
            .iter()
            .enumerate()
            .map(|(i, d)| {
                #[allow(clippy::cast_possible_truncation)]
                let e = d["embedding"]
                    .as_array()
                    .expect("embedding")
                    .iter()
                    .filter_map(Value::as_f64)
                    .map(|x| x as f32)
                    .collect();
                (d["index"].as_u64().unwrap_or(i as u64), e)
            })
            .collect();
        data.sort_by_key(|(i, _)| *i);
        assert_eq!(data.len(), batch.len(), "one vector per input");
        out.extend(data.into_iter().map(|(_, e)| e));
    }
    out
}

fn percentile(v: &mut [f32], p: f64) -> f32 {
    v.sort_by(f32::total_cmp);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_precision_loss)]
    let i = (((v.len() - 1) as f64) * p).round() as usize;
    v[i]
}

#[tokio::test]
async fn knn_leave_one_out_against_a_real_embedder() {
    let Some(url) = env("CALIBAN_KNN_EVAL_URL") else {
        eprintln!("knn_eval skipped: set CALIBAN_KNN_EVAL_URL (and CALIBAN_KNN_EVAL_MODEL) to run it");
        return;
    };
    let model = env("CALIBAN_KNN_EVAL_MODEL").expect("CALIBAN_KNN_EVAL_MODEL");
    let key = env("CALIBAN_KNN_EVAL_API_KEY");
    let prefix = env("CALIBAN_KNN_EVAL_PREFIX").unwrap_or_default();
    let dataset = match env("CALIBAN_KNN_EVAL_DATASET") {
        Some(p) => {
            IntentDataset::from_json(&std::fs::read_to_string(&p).expect("dataset file")).expect("valid dataset")
        }
        None => IntentDataset::builtin(),
    };
    let mut params = KnnParams::default();
    if let Some(k) = env("CALIBAN_KNN_EVAL_K") {
        params.k = k.parse().expect("CALIBAN_KNN_EVAL_K");
    }
    if let Some(t) = env("CALIBAN_KNN_EVAL_TEMPERATURE") {
        params.temperature = t.parse().expect("CALIBAN_KNN_EVAL_TEMPERATURE");
    }

    let (mut texts, mut intents) = (Vec::new(), Vec::new());
    for (intent, spec) in &dataset.intents {
        for u in &spec.utterances {
            texts.push(format!("{prefix}{u}"));
            intents.push(intent.clone());
        }
    }
    let client = reqwest::Client::new();
    let started = std::time::Instant::now();
    let vectors = embed(&client, &url, &model, key.as_deref(), &texts).await;
    let embed_ms = started.elapsed().as_millis();
    let owners = vec![None; texts.len()];
    let index = KnnIndex::build(vectors, &intents, &owners).expect("index");
    let r = index.leave_one_out(&params);

    println!(
        "kNN leave-one-out: model {model}, {} exemplars, {} intents, dim {}, k {}, T {} (embedded in {embed_ms} ms)",
        r.n,
        index.intents().len(),
        index.dim(),
        params.k,
        params.temperature
    );
    println!(
        "  top-1 accuracy {:.3} | accepted precision {:.3} | abstain rate {:.3} (default_threshold {})",
        r.top1_accuracy(),
        r.accepted_precision(),
        r.abstain_rate(),
        params.default_threshold
    );
    for (intent, c) in &r.per_intent {
        #[allow(clippy::cast_precision_loss)]
        let acc = c.top1_correct as f64 / c.n.max(1) as f64;
        println!("  {intent:<14} n={:<3} top-1 {acc:.3}", c.n);
    }
    let mut confusions: Vec<_> = r.confusion.iter().filter(|((t, p), _)| t != p).collect();
    confusions.sort_by(|a, b| b.1.cmp(a.1));
    for ((t, p), n) in confusions.iter().take(8) {
        println!("  confused {t} -> {p}: {n}");
    }

    // OOS top-1 similarity, to seed `oos_threshold`.
    if !dataset.oos.is_empty() {
        let oos_texts: Vec<String> = dataset.oos.iter().map(|u| format!("{prefix}{u}")).collect();
        let mut oos: Vec<f32> = embed(&client, &url, &model, key.as_deref(), &oos_texts)
            .await
            .iter()
            .map(|v| index.classify(v, None, &params).expect("classify").top1_similarity)
            .collect();
        println!(
            "  OOS top-1 similarity: p50 {:.3}, p90 {:.3}, max {:.3} ({} examples); a starting point for oos_threshold; calibrate it with ml's knn-eval",
            percentile(&mut oos, 0.5),
            percentile(&mut oos, 0.9),
            percentile(&mut oos, 1.0),
            oos.len()
        );
    }

    if let Some(min) = env("CALIBAN_KNN_EVAL_MIN_ACCURACY") {
        let min: f64 = min.parse().expect("CALIBAN_KNN_EVAL_MIN_ACCURACY");
        assert!(r.top1_accuracy() >= min, "top-1 accuracy {:.3} < {min}", r.top1_accuracy());
    }
}
