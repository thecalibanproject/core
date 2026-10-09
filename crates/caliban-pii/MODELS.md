# caliban-pii models

Models that `caliban-pii` runs in-process. Every one must run fully offline and carry a licence
that allows **commercial on-prem redistribution** (Caliban ships them inside customer networks).
Licence policy and artifact contract: `ml/README.md`, `ml/src/caliban_ml/artifacts/`.

## PII NER (L1)

### Chosen model

| | |
|---|---|
| Artifact | `nym-pii-multilingual-small-int8` v3.0.0 (`kind: pii_ner`) |
| Upstream | [`Wismut/nym-pii-multilingual-small`](https://huggingface.co/Wismut/nym-pii-multilingual-small), `int8/` variant |
| Pinned revision | `4348999cd3c2e20c49615e9af7c6bbb45b64cd85` |
| Files | `model.onnx` (138.7 MB, sha256 `139006ae…190286`), `tokenizer.json` (12.4 MB, `c299144e…47d8de`), `config.json` |
| Architecture | mmBERT-small (ModernBERT), depth-pruned to 16 layers, hidden 384, vocab pruned to 199k tokens; int8 embeddings + fp16 body weights, fp32 compute. ONNX opset 18; inputs `input_ids`, `attention_mask` (int64); output `logits` `[batch, seq, 81]` |
| Labels | IOB2, 40 entity types / 81 labels (`GIVEN_NAME`, `SURNAME`, `COMPANY_NAME`, `CITY`, `STREET_ADDRESS`, `EMAIL`, `PHONE`, `IBAN`, `PASSPORT`, `API_KEY`, …) |
| Languages | ~23: en de fr es it pt nl pl sv cs ro tr fi da el ru uk ja zh ko ar hi |
| Weights licence | **MIT**: HF API `cardData.license = "mit"` at the pinned revision; the card's License section says "MIT (inherited from mmBERT-small)" |
| Base model | `jhu-clsp/mmBERT-small`: `cardData.license = "mit"` |
| Training data | (1) [`Wismut/nym-pii-multilingual-data`](https://huggingface.co/datasets/Wismut/nym-pii-multilingual-data) @ `abe23bf0…`: 724.5k synthetic, Faker-filled examples, `cardData.license = "mit"`, no real personal data. (2) ~77.5k Wikipedia passages auto-labelled by `google/gemma-4-26B-A4B` (`cardData.license = "apache-2.0"`). The text is CC-BY-SA-4.0 and is **not** redistributed. |

Why this one: it is the only candidate that is permissively licensed, multilingual,
PII-specific (not only PER/ORG/LOC) and ships a ready ONNX export with a `tokenizer.json`
the Rust `tokenizers` crate loads. It is also small (139 MB) and does plain BIO token
classification, so no span-decoding heuristics beyond IOB2 are needed. The card reports
(int8): real-text F1 76.4, ai4privacy OOD 67.2, non-Latin char-F1 71.7, and REDACT
benchmark 0.507, on par with the OpenAI Privacy Filter.

**Open licence item (human sign-off needed before bundling).** `ml`'s policy classifies
the CC-BY-SA-4.0 Wikipedia source text used for fine-tuning as `review_required`. The
fetch script records it in `data_card.training_datasets`, so `caliban-ml manifest verify`
fails until someone adds a `licence_overrides` entry
(`fetch_pii_ner.py --approved-by 'Name <email>' --approval-reason '…'`). The artifact is
fine for development before then. The same applies to the CoNLL-2003 data (Reuters,
research agreement) behind the English fallback.

### Also packaged: English fallback

`distilbert-ner-en` 1.0.0 is [`dslim/distilbert-NER`](https://huggingface.co/dslim/distilbert-NER)
@ `dfa2838a127384aabb82ed7719e16dab84c42a2a`. Weights are Apache-2.0
(`cardData.license = "apache-2.0"`). It is English CoNLL-2003 with PER/ORG/LOC/MISC labels,
fp32, 261 MB, inputs `input_ids` and `attention_mask`, opset 11. It scores better on
ORG/LOC in English news-style prose and does not do PII types. Fetch it with
`--preset distilbert-ner-en`.

### Rejected

| Candidate | Licence (HF `cardData.license`) | Why not |
|---|---|---|
| `Babelscape/wikineural-multilingual-ner` | cc-by-nc-sa-4.0 | Non-commercial. |
| `iiiorg/piiranha-v1-detect-personal-information` | cc-by-nc-nd-4.0 | Non-commercial; trained on ai4privacy data. |
| `urchade/gliner_base`, `gliner_multi` (v1) | cc-by-nc-4.0 | Non-commercial. |
| `urchade/gliner_multi_pii-v1`, `knowledgator/gliner-pii-base-v1.0` | apache-2.0 | GLiNER span model. It needs label prompts, word splitting and span-matrix decoding, which means more Rust surface to get right. Pretraining (Pile-NER) is GPT-labelled. Keep it as a candidate for per-tenant zero-shot labels later. |
| `openai/privacy-filter` | apache-2.0 | 1.4B-parameter MoE: the ONNX export is 5.6 GB fp32 and 0.9 GB q4. English-first, has no ORG/LOC labels, and uses BIOES (the decoder already supports BIOES). Too heavy for the default L1. |
| `Wismut/nym-pii-multilingual` (base) | mit | Same family as the default, 3× larger (359 MB int8), +2–3 F1. A drop-in upgrade if latency allows. |
| `Davlan/bert-base-multilingual-cased-ner-hrl` (+ `Xenova/` ONNX) | afl-3.0 | Permissive, but not on the allow-list (review). PER/ORG/LOC only. Mixed news corpora. |
| `dslim/bert-base-NER` / `Xenova/bert-base-NER` | mit | English CoNLL only. `distilbert-NER` is the lighter equivalent. |
| `OpenMed/OpenMed-PII-*` | apache-2.0 | Clinical-domain. No ONNX in repo. Weaker out of domain per the nym benchmarks. |
| `FacebookAI/xlm-roberta-large-finetuned-conll03-english` | none on the card | No licence field. 560M parameters. |

### Fetch, verify, point Caliban at it

```sh
cd ml
python3 scripts/fetch_pii_ner.py --list
python3 scripts/fetch_pii_ner.py                                  # default preset
# → ml/artifacts/pii_ner/nym-pii-multilingual-small-int8/3.0.0/{manifest.json,model.onnx,tokenizer.json,config.json}
.venv/bin/caliban-ml manifest verify artifacts/pii_ner/nym-pii-multilingual-small-int8/3.0.0 --strict
```

The script is stdlib-only and safe to run on the training box. It does the following:

- Downloads from `https://huggingface.co/<repo>/resolve/<pinned revision>/<file>`.
- Refuses any file whose sha256 (LFS) or git blob id does not match the value **pinned in the
  script**.
- Reads the ONNX inputs, outputs and opset from the graph.
- Takes the labels from `config.json` `id2label`.
- Writes `manifest.json`, then runs `caliban-ml manifest verify --strict`.
- Exits 3 while a licence review is pending.

Fetched artifacts are git-ignored. Ship them through the bundle pipeline, signed, as usual.

In Rust, behind cargo feature `ner`, which is off by default:

```rust
use caliban_pii::{NerDetector, NerOptions, PiiEngine};
let ner = NerDetector::load(Path::new(&dir), NerOptions::default())?; // verifies every sha256 first
let engine = PiiEngine::default().with_detector(ner);
```

The binary wires `CALIBAN_PII_NER_DIR` → `NerDetector::load`. `load`:

- Rejects an unknown `manifest_version` or a kind other than `pii_ner`.
- Rejects any path that is illegal or escapes the directory through a symlink, and any file
  whose size or sha256 does not match.
- Reads model and tokenizer bytes once, then hashes and loads those same bytes, so there is no
  TOCTOU window.
- Binds ONNX tensors by the names in the manifest and cross-checks them against the graph.

It does **not** check the `manifest.json.minisig` signature yet. Deployments that require
signed artifacts must check it before calling `load`.

Build: `ort` uses `download-binaries`, which fetches a prebuilt ONNX Runtime **at build time
only**. For air-gapped builds, point `ORT_LIB_LOCATION` at a vendored ONNX Runtime (see the
`ort` docs). Switching to `load-dynamic` + `ORT_DYLIB_PATH` is a one-line feature change in
`Cargo.toml`. Nothing is downloaded at runtime.

### Runtime behaviour and knobs (`NerOptions`)

- **Windows**: the text is tokenized once. The body is cut into windows of `max_tokens`
  (512 by default, specials included) with `overlap` = 128 shared tokens. Windows run in
  batches of `batch_size` = 4.
- **Stitching**: each token takes its prediction from the window where it is most central, so
  nothing is decoded twice.
- **Decoding**: accepts IOB2, IOB1-tolerant input, BIOES/BILOU and IO. Spans are byte offsets
  into the original `&str`, snapped to char boundaries and trimmed of surrounding
  whitespace/punctuation.
- **Aggregation**: `Token` for BPE/SentencePiece models; `First` for WordPiece (BERT) models,
  which label the first sub-word.
- **Thresholds**: `default_threshold` = 0.5 (the mean tag probability of the entity), and
  `thresholds` per model label.
- **Label mapping**: `ner::default_label_map`, with per-label overrides in `label_map`:
  - `PER` / `GIVEN_NAME` / `SURNAME` → `Person`, joining adjacent given name + surname.
  - `ORG` / `COMPANY_NAME` → `Organization`.
  - `LOC` / `CITY` / `STREET_ADDRESS` … → `Location`, a new variant. Its surrogate is an
    invented town name, or "N Maple Road" when the original has a number.
  - Structured IDs → `Custom(<LABEL>)`, which gets shape-preserving surrogates.
  - Model-detected credentials → `Custom("CREDENTIAL")`. They are not mapped to `Secret`,
    because a false positive would block the request.
  - Ignored: `MISC`, `DATE`, `TIME`, `AGE`, `GENDER`, `COUNTRY`, `STATE`, `URL`.
- **Concurrency**: `sessions` independent ONNX sessions, each behind a `Mutex` (`run` needs
  `&mut Session`), with `intra_threads` ONNX threads each. `NerDetector` is `Send + Sync`.
- **Failure**: an inference error makes `PiiEngine::protect` return
  `PiiError::DetectorFailed`, so the request fails closed. `Detector::detect` is best-effort
  and counts failures in `NerDetector::failures()`.

### Measured (dev machine, see the crate report for numbers)

Run the eval and benchmark yourself:

```sh
CALIBAN_PII_NER_DIR=$PWD/../ml/artifacts/pii_ner/nym-pii-multilingual-small-int8/3.0.0 \
  cargo test --release -p caliban-pii --features ner --test ner_integration -- --nocapture --test-threads=1
cargo run --release -p caliban-pii --features ner --example ner_bench -- "$CALIBAN_PII_NER_DIR"
```
