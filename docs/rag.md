# Retrieval (RAG)

Nodes search a tenant's documents with the built-in tool `builtin://rag_search`. Documents are
managed on the admin API, indexed by workers through the gateway's own embedding path, and kept in
one Qdrant collection per document collection. The design follows research note 06 (RAG and token
efficiency) with its 2026-10-11 delta check, notes 01 and 05 for the vector store and personal
data, and note 04 for taint; the deviations are listed at the end. Crates: `caliban-rag` (the
library), `caliban-gateway::rag` (the tool and the services it uses), `caliban-cp::rag` (the admin
API).

## In short

- **Collections** belong to one tenant and name an embedding model (and optionally a rerank
  model) from the catalogue that the tenant can reach. Nodes name them in their scopes:
  `rag.<collection>:read` (or `rag.*:read`) in `datasources.scopes`.
- **Ingest** seals the document under the tenant's data key and leaves it `pending`. A worker
  parses it with its structure, cuts it into chunks that carry their heading path, scans every
  chunk for injections, compares untrusted documents with the collection for near-duplicates,
  pseudonymises personal data, embeds through `/v1/embeddings` (in process), and writes dense and
  BM25 vectors, plus a navigation tree for long documents.
- **Nothing is visible until it is ready**: a version is served only once it is indexed and its
  checks passed. A flagged document is `quarantined` until an administrator releases it.
- **Search** fuses dense and BM25 results with reciprocal rank fusion, checks every candidate
  against the registry, walks the navigation trees of long documents for multi-evidence
  questions, reranks through `/v1/rerank`, drops exact duplicates, applies a near-duplicate
  penalty only to redundant pools, and assembles the passages under a token budget with
  citations.
- **Results are data.** They carry the `retrieved` taint label: a write whose arguments derive
  from them needs an `allow_tainted` entry or a human approval.

## Collections and documents (admin API)

All under `/api/v1/tenants/{t}/rag/collections`. Every write is audited in the hash chain (the
registry writes the event in the transaction of the change, the control plane records it at
once). Document content is never returned by any endpoint.

| Endpoint | Permission | Audit |
|---|---|---|
| `GET /rag/collections` (each with `document_counts`: documents per status, newest version of each) | `rag.read` | |
| `GET /rag/models` (the `embedding` and `rerank` models the tenant can reach, for the collection form) | `rag.read` | |
| `POST /rag/collections` `{"name", "embedding_model", "rerank_model"?, "description"?, "settings"?}` | `rag.write` | `rag.collection.create` |
| `GET /rag/collections/{c}` (with `used_by`: the published versions that name it) | `rag.read` | |
| `DELETE /rag/collections/{c}` (`409` while a published version names it; `rag.*:read` does not hold it) | `rag.write` | `rag.collection.delete` |
| `GET /rag/collections/{c}/documents?status=&cursor=&limit=` (newest version of each document, with `live_version`) | `rag.read` | |
| `POST /rag/collections/{c}/documents` `{"doc_id", "content", "title"?, "content_type"?, "source"?, "trust"?, "valid_from"?, "valid_to"?}` | `rag.write` | `rag.document.ingest` |
| `GET /rag/collections/{c}/documents/{doc_id}` (every version: status, chunks, tokens, PII count, findings with their `heading_path`, `vet_deadline_at` for untrusted documents) | `rag.read` | |
| `DELETE /rag/collections/{c}/documents/{doc_id}` | `rag.write` | `rag.document.delete` |
| `POST /rag/collections/{c}/documents/{doc_id}/release` `{"version", "acknowledge_findings": true}` | `rag.approve` | `rag.document.release` (with the findings) |

| Role | `rag.read` | `rag.write` | `rag.approve` |
|---|---|---|---|
| `owner`, `admin`, `tenant_admin` | yes | yes | yes |
| `developer` | yes | yes | no |
| `viewer`, `auditor` | yes | no | no |
| `billing` | no | no | no |

Releasing a quarantined document is kept apart from ingesting it, like approving a tool manifest
is kept apart from registering its server.

**Collection settings** (all optional):

| Setting | Default | Meaning |
|---|---|---|
| `chunk_tokens` | 384 | Largest chunk, in estimated tokens (64 to 2048) |
| `default_trust` | `untrusted` | Trust of documents ingested without one |
| `nav_min_chunks` | 24 | Documents with at least this many chunks get a navigation tree |
| `vet_deadline_secs` | 900 | An untrusted document whose checks have not passed this long after ingest (or after its release) fails and stays invisible |

The embedding model is fixed for a collection's life (vectors of two models are not comparable):
to change it, create another collection and ingest again.

**Documents.** `doc_id` is 1 to 200 visible ASCII characters without `/`; it and `source` are
stored in clear in the registry, so they must not carry personal data (the title and the content
are sealed). Formats: `text/markdown` (default), `text/html`, `text/plain`. **PDF is refused**: no
permissively licensed, pure-Rust PDF extractor is vendored in `core`, so convert PDFs (and office
formats) to Markdown or text before ingesting. At most 5 MB of text per document.

Each ingest adds a version. Ingesting the same content and settings as the newest version again
changes nothing (`200`, `unchanged: true`). A new version replaces the previous one only when it
becomes ready, in one transaction; until then the previous version is served.

| State | Served | Meaning |
|---|---|---|
| `pending`, `indexing` | no | Waiting for, or being indexed by, a worker |
| `ready` | **yes** | Indexed, checks passed |
| `quarantined` | no | A check flagged it; release it to index it again with the findings acknowledged |
| `failed` | no | Indexing failed for good (bad content, a credential in the text, the vetting deadline) |
| `superseded`, `deleted` | no | Replaced by a newer ready version, or deleted |

## Ingest

1. **Parse with structure.** Markdown (ATX and setext headings, fenced code, lists, pipe tables),
   HTML (headings, paragraphs, lists, tables, `pre`; scripts, styles and comments dropped;
   entities decoded) and plain text (paragraphs). Every block knows its heading path.
2. **Chunk.** A chunk never crosses a heading boundary; blocks of one section are packed up to
   `chunk_tokens` with no overlap; an oversized block is split at sentences (or lines, for code
   and tables), then words. What is embedded and indexed is the chunk with its document title and
   heading path in front. In a pre-registered, placebo-controlled ablation, structure-aligned
   chunks with their real heading paths beat LLM-written chunk context and a shuffled-heading
   placebo for dense retrieval, at no LLM cost (arXiv 2610.10170, preprint); naive two-stage
   section-then-chunk retrieval hurt and is not used. Embedding-based semantic chunking is not
   used either (arXiv 2410.13070). Token counts are estimates (about four characters per token,
   the gateway's estimate), computed once at ingest.
3. **Poisoning controls** (note 06, "Corpus poisoning"):
   - every chunk goes through the injection scan Caliban runs on tool manifests (instructions to
     the model, hidden characters, exfiltration requests, URLs);
   - an untrusted document's chunks (the first 64) are compared with the ready chunks of the
     other documents of the collection: a near-identical chunk (cosine 0.97 or more) is a
     `near_duplicate` finding, since PoisonedRAG-style attacks plant near-copies of target
     passages (arXiv 2402.07867, 97% attack success with 5 injected texts);
   - **trust tiers**: a trusted source's findings are recorded, and only hidden characters
     quarantine it; an untrusted source is quarantined by any finding other than a URL;
   - **vetting deadline**: an untrusted document whose checks have not passed within the
     collection's `vet_deadline_secs` fails, rather than becoming visible later when a backlog
     clears (fail closed; a verifier backlog let poisoned chunks through in arXiv 2610.05826,
     preprint). The window runs from ingest, or from the release of a quarantined version: a
     release is an administrator's decision on the findings and sends the version back to be
     indexed, so it gets a fresh window (a backlog after the release still fails it closed).
     Documents show the time as `vet_deadline_at`;
   - **locating findings**: each finding names its chunk and the headings above it
     (`heading_path`, pseudonymised, at most 80 characters each, hidden characters removed), never
     an excerpt of the text that triggered it.

   Per-document checks miss sets of individually benign documents that jointly redirect answers
   (LENS, arXiv 2609.35155, preprint), so provenance (who ingests what, with which trust) stays
   the main control, and the `retrieved` taint label is what makes an injection harmless to
   writes.
4. **Personal data.** The indexed text is pseudonymised with the tenant's PII engine before it is
   embedded or turned into BM25 terms (note 05 §5.1: never embed raw PII), with the tenant's
   **tenant-scope** surrogate key whatever its request surrogate scope, so a person gets the same
   surrogate in every document and in every query. Embedders outside the trust boundary then get
   masked text, as on `/v1/embeddings`. A credential in the text fails the document. The original
   text is stored only sealed.
5. **Embed** through the gateway's `/v1/embeddings`, in process, as the tenant's own background
   work (no API key: the tenant's limits apply, not a key's), in batches of 32: the tenant's route
   to the model (on-prem embedders included), quotas, metering and tracing apply.
6. **Write** the points `pending`, then flip them to `ready` once every point is written and the
   checks passed; the registry is told last. Until then nothing of the version is visible.

## Storage

- **Registry** (Postgres, migration `0029_rag.sql`, next to the node journal; in memory for a
  standalone process without a database): collections, document versions with their state,
  findings and sealed content (wiped once a version is superseded, deleted or failed), leases.
  Per-tenant row-level security like the journal.
- **Vectors** (Qdrant over REST, like the semantic cache): one Qdrant collection per document
  collection, `{prefix}_{collection id}`, so each tenant's vectors live in physically separate
  collections (note 05 §5.2; RAG membership inference makes shared indexes a leak, arXiv
  2405.20446). Each point holds a dense vector of the pseudonymised text, a BM25 sparse vector,
  a keyed hash of the document id (`doc_key`), the version, its state, and the chunk's text, title,
  heading path and document id **sealed under the tenant's data key**. BM25 term ids are a keyed
  hash with a key derived from the data key, so a dump of the index is not a readable bag of words.
  Nothing readable without the tenant's key is stored in Qdrant except the vectors themselves,
  which are of pseudonymised text (note 05: treat embeddings as personal data).
- **Deletes.** Deleting a document or a collection stops serving it at once (the registry);
  workers then delete the points or drop the Qdrant collection. Deleting a tenant deletes its
  collections; its data key is destroyed with the tenant, which makes every sealed chunk
  unreadable (crypto-shredding).

## Search

1. **Hybrid.** The query is pseudonymised like the documents, embedded through `/v1/embeddings`
   as the run's invoking key (usage tagged with the node run), and turned into keyed BM25 terms.
   Each collection is searched on both legs (40 candidates each); every list is fused with
   reciprocal rank fusion (k = 60; Cormack et al. 2009). Anthropic's contextual retrieval reported
   35% fewer failed retrievals from embeddings, 49% with BM25 added and 67% with a reranker.
2. **Visibility gate.** Every candidate's document version is checked against the registry; only
   `ready` versions pass. If the registry cannot answer, the search fails (fail closed).
3. **Navigation** (NavTree, arXiv 2610.06902, preprint). For a question that needs several pieces
   of evidence (`evidence: "multi"`) or a search inside one document (`doc_id`), the long
   documents among the best candidates are walked through their navigation trees: a deterministic
   balanced tree over the chunks (4 children per node, zero LLM calls at indexing; an inner node's
   vector is the mean of its chunks' vectors and its BM25 vector covers their text), walked with
   both legs fused level by level, keeping the 3 best nodes, emitting only chunks. The chunks
   reached join the candidates the reranker sees; they never reorder the flat ranking (fused as a
   ranking of their own, they displaced better flat results in the eval below).
4. **Rerank** through `/v1/rerank` when the collection names a rerank model (top 30 candidates).
   After a rerank, passages more than 0.5 below the best one are dropped (a score cliff).
5. **Duplicates and diversity.** Exact duplicates (same keyed content hash) are always dropped. A
   near-duplicate penalty (maximal marginal relevance, lambda 0.5) applies only when the question
   needs several pieces of evidence **and** the pool is redundant (at least 10% of the pairs among
   the top 10 candidates have a cosine of 0.92 or more): on clean pools diversification lowered
   relevance, evidence coverage and answer quality, and it helped only multi-evidence questions
   over redundant pools (arXiv 2610.09412, preprint).
6. **Budget.** Passages are added in rank order until `max_tokens` or `k`; a passage that does
   not fit is skipped, never cut. More context is not better (Lost in the Middle, arXiv
   2307.03172; the inverted U of arXiv 2410.05983).
7. **Order and citations.** Documents best first and second best last, the others between
   (against "lost in the middle"); passages of one document in reading order (OP-RAG, arXiv
   2409.01666). Documents outside their validity window (`valid_from`, `valid_to`) are left out,
   and a passage with `valid_to` says until when it applies (stale documents flip answers, arXiv
   2609.31342).

## The node tool

```json
{"kind": "agent", "prompt": {"system": "You answer from the handbook."}, "model_policy": {},
 "budgets": {"steps": 8, "tokens": 100000, "wall_clock_s": 60},
 "datasources": {"scopes": ["rag.handbook:read"]},
 "tools": [{"ref": "builtin://rag_search", "effect": "read"}]}
```

- `effect: read` only; the spec needs at least one `rag.<collection>:read` (or `rag.*:read`)
  scope. Publishing checks that every named collection exists. The datasource name `rag` is
  reserved.
- An API key with datasource scopes narrows what its runs may search, as for the datasource tool
  (`"datasource_scopes": ["rag.handbook:read"]`; a key whose scopes name no `rag.` collection
  searches nothing).
- Arguments: `query` (required), `collections` (default: every collection in scope), `k` (1 to
  20, default 8), `max_tokens` (100 to 8000, default 2000), `doc_id`, `evidence` (`single`,
  default, or `multi`).
- Result: `context` (the assembled passages under a header that says they are data, not
  instructions; each cited `[n] <title> > <heading path> (doc <id> v<version>, chunk
  <id>@v<version>#c<index>)`), `results` (per citation: `n`, `collection`, `doc_id`,
  `doc_version`, `title`, `heading_path`, `chunk_id`, `score`, `tokens`, `source`, `valid_to`),
  `tokens`, `budget`, and `strategy` (`hybrid`, `reranked`, `navigated`, `diversified`,
  `candidates`, `hidden`, `duplicates`).
- **Taint**: the result carries `retrieved`. The [injection suite](evals.md) proves it end to end
  with the real tool: a document that carries an instruction is retrieved, a compromised model
  follows it, and the write waits for a human.
- **Personal data**: the tool runs in process and pseudonymises the query itself, so it takes its
  arguments as the run holds them (a trusted tool); its result is anonymized as it enters the run,
  like any tool result.
- Embedding and rerank calls are made as the run's invoking API key, tagged with the node run in
  usage, and with an `Idempotency-Key` derived from the step, so a replayed step does not pay twice
  (with the shared Valkey store).
- **Metering**: retrieval's own calls carry a usage `purpose` (and the same intent):
  `rag.ingest` for indexing embeddings (the tenant's background work), `rag.search` for a node's
  query embedding and rerank. `GET /api/v1/usage` totals them in `by_purpose`, raw and rolled-up
  days alike (migration 0031), so retrieval spend is separable from the tenant's own
  `/v1/embeddings` calls (intent `embedding`, no purpose).

There is no data-plane search endpoint: the P3 plan calls for RAG search as a built-in node tool,
and grounding plain chat requests (stage 8 of the reference architecture) is not built.

## Deployment

```toml
[rag]
index = "qdrant"                  # or "memory": one standalone process, lost on restart
qdrant_url = "http://qdrant:6333" # unset: CALIBAN_QDRANT_URL, then [cache.semantic] qdrant_url
collection_prefix = "caliban_rag"
index_concurrency = 2             # documents one process indexes at once
```

- **Where indexing runs:** workers (split mode) and standalone processes, next to node runs. A
  control plane only writes the registry. Without a Qdrant URL (and without `index = "memory"`),
  documents are not indexed and `rag_search` is unavailable (logged at start).
- **Qdrant 1.19.2 or later** for production: every search is filtered (`state = ready`), and
  earlier versions could return no results when the HNSW entry point did not match the filter
  (note 06). Small collections are searched exactly and are not affected. The CI service and
  the test commands use 1.19.2.
- **Worker database role:** add `GRANT SELECT, UPDATE ON rag_collection, rag_document TO
  caliban_worker;` (see [nodes.md](nodes.md#where-runs-execute)). Workers never insert or delete
  registry rows.
- **Snapshots:** a tenant's wrapped data key now travels in the snapshot whenever the tenant has
  one (workers index documents of tenants without nodes). It is wrapped by the KEK, like the data
  key inside every sealed BYOK key of the snapshot.

## Evals

`cargo test -p caliban-rag --test eval -- --nocapture` prints recall@k and nDCG@10 on a small
synthetic labelled set (a fictional company's documents, written for the eval), per pipeline
stage, per question type, for navigation on long manuals with hard negatives, and for the
diversity penalty on near-duplicate pools; floors in the test guard against regressions. The
embedder and reranker are deterministic stand-ins (`caliban_rag::eval`), not models: the numbers
show that each mechanism does what it is meant to on data built to exercise it, not how retrieval
performs with a real embedder on real documents. Measured on 2026-10-11:

| Set A (22 questions) | recall@5 | recall@10 | nDCG@10 |
|---|---|---|---|
| Dense, fixed windows without heading paths | 0.909 | 0.909 | 0.808 |
| Dense, structure-aware chunks with heading paths | 0.955 | 0.955 | 0.854 |
| Hybrid (dense + BM25, RRF) | 1.000 | 1.000 | 0.907 |
| Hybrid + rerank (the default) | 1.000 | 1.000 | 1.000 |

By question type (recall@10 / nDCG@10): heading paths lift heading-dependent questions ("reset
the Z900", where only the heading names the product) from 0.67 / 0.48 to 0.83 / 0.71; BM25 lifts
identifiers (`ERR-4471`) from 0.85 to 1.00 nDCG and heading-dependent questions to 1.00 recall;
the reranker brings every type to 1.00 nDCG. On paraphrases, heading paths cost a little nDCG with
dense retrieval alone (0.97 to 0.93), which the reranker recovers.

| Set B (long manuals, two facts each, multi-evidence) | recall@4 |
|---|---|
| Flat hybrid / with navigation (no reranker) | 0.750 / 0.750 |
| Flat hybrid + rerank / with navigation | 1.000 / 1.000 |
| Shallow pool (2 candidates per leg) + rerank: flat / with navigation | 0.875 / 1.000 |

Navigation helps where the flat candidate pool is shallow compared with the corpus, which the
shallow pool stands for; with a full pool and a reranker the flat search already finds both facts.

| Diversity | Set C evidence coverage@2 (redundant pools) | Set A nDCG@10 (clean pools) |
|---|---|---|
| Off | 0.500 | 1.000 |
| Conditional (the default) | 0.750 | 1.000 |
| Always | 0.750 | 1.000 |

The penalty raises evidence coverage on redundant pools; on the travel question it surfaced the
expense policy (also about business trips) rather than the insurance page, so it diversifies
without targeting the missing evidence. This set shows no cost of always-on diversity on clean
pools (the paper measured one); the default stays conditional, as the paper recommends.

Run the same harness against a real embedder and reranker and a labelled sample of a tenant's own
documents before drawing quality conclusions; it is also how an eval-gated upgrade (below) should
be decided.

## Where this differs from note 06

- **BM25 in Qdrant, not tantivy.** Workers are stateless and share only Postgres and Qdrant; a
  tantivy index on a worker's disk would need its own replication. Qdrant's sparse vectors with
  the `idf` modifier give BM25 next to the dense vectors, and the term ids are keyed per tenant.
- **One Qdrant collection per document collection**, not a shared collection with an `is_tenant`
  payload index (note 01's pattern for the semantic cache). Note 05 §5.2 asks for physically
  separate namespaces for RAG; the number of collections stays small.
- **Navigation is candidate generation** for the reranker, not a ranking signal (the eval above).
- **Token counts are estimates**, not the embedder's tokenizer: the gateway does not have every
  provider's tokenizer.
- **Not built** (later work): LLM-written chunk context as the eval-gated upgrade for documents
  without usable structure (note 06 makes it eval-gated; nothing turns it on yet), late chunking,
  Matryoshka two-stage search and quantisation, a strategy head on the router (`none` /
  `single_shot` / `iterative` / `full_context`), CRAG-style confidence bands, query rewriting and
  HyDE, load-adaptive rerank depth, extractive compression, retrieval and answer caches keyed by
  document versions, per-document ACLs (the collection is the access unit), `superseded_by`
  links between documents, document-level access for end users, and PDF or office formats.
