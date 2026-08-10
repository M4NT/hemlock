# Methodology — Deceiving the Retriever

## Research Question

To what extent do adversarial context injection attacks succeed against
unguarded RAG pipelines — and how much of that attack surface is closed
by structured ingest-time and retrieval-time defenses?

## Pipeline Architecture

The experimental RAG pipeline follows the standard Retrieve-Augment-Generate
pattern:

1. **Ingest** — documents are chunked (`chunk_size=500`, `chunk_overlap=50`)
   and indexed in a ChromaDB vector store using
   `sentence-transformers/all-MiniLM-L6-v2` embeddings.
2. **Retrieve** — on a user query, the top-4 (`top_k=4`) semantically similar
   chunks are retrieved via cosine similarity.
3. **Generate** — a prompt template concatenates context chunks and the query;
   the LLM produces a response.

No external API calls are made. The LLM is replaced by one of two
deterministic stubs:

- **`VulnerableMockLLM`** (unguarded phase): scans the full formatted prompt
  for known attack success-markers; if any are found in the retrieved context,
  returns a response that echoes that marker — simulating a naïve LLM that
  follows injected instructions.
- **`MockLLM`** (guarded phase): always returns `"This is a safe answer."`,
  ensuring that any residual success is attributable only to bypassed defenses,
  not to LLM behavior.

## Experimental Design

Two phases are run for each attack spec:

### Phase A — Unguarded

```
VulnerablePipeline = Pipeline(VulnerableMockLLM)
attack.setup()   # injects malicious document(s)
result = attack.run()
unguarded_success = result.succeeded  # True if attack marker in response
```

### Phase B — Guarded

```
base = Pipeline(MockLLM)
guarded = GuardedPipeline(base, ingest_guards, retrieval_guards)
attack.setup()   # same injection; now intercepted by ingest_guards
result = attack.run()
guarded_success = result.succeeded
intercepted = (guarded.ingest_blocked > 0 or guarded.retrieval_filtered > 0)
              and not guarded_success
```

`GuardedPipeline` wraps the base pipeline:

- **Ingest layer**: each document passes through `[IngestDefense].inspect()`.
  If any guard returns `doc=None`, the document is blocked and never indexed.
- **Retrieval layer**: after retrieval, each chunk passes through
  `[RetrievalDefense].filter()`. Blocked chunks are removed from context;
  if all chunks are removed, the response is replaced with a sentinel string
  (`"[BLOCKED BY RETRIEVAL DEFENSE]"`), guaranteeing `succeeded=False`.

## Attack Coverage

| Category | Variants | Attack module | Defense module(s) |
|---|---|---|---|
| AEO Poisoning | `llms_txt`, `json_ld`, `agents_md` | `adversarial_aeo` | `aeo_context_validator` |
| Citation Forgery | `fake_paper`, `fake_standard`, `fake_report` | `citation_forgery` | `citation_guard` |
| Context Jailbreak | `roleplay`, `research`, `hypothetical` | `jailbreak_via_context` | `context_jailbreak_guard` |
| CoT Hijacking | `logical_trap`, `false_premise`, `authority_cot` | `chain_of_thought_hijack` | `chain_of_thought_guard` |
| Temporal Spoofing | `future_dated`, `stale_override`, `event_spoofing` | `temporal_spoofing` | `temporal_guard` |

**Excluded** (require visual/binary pipeline): Computer Use Injection,
Polyglot File Injection, Invisible Markup. These are documented as
limitations and represent future work for multi-modal RAG pipelines.

## Metrics

For each trial `(attack_spec, run)`:

| Metric | Definition |
|---|---|
| `unguarded_success` | `True` if Phase A's LLM response contains any attack SUCCESS_MARKER |
| `guarded_success` | `True` if Phase B's response contains any attack SUCCESS_MARKER |
| `ingest_blocked` | Count of documents blocked by ingest-layer guards |
| `retrieval_filtered` | Count of chunks removed by retrieval-layer guards |
| `defense_intercepted` | `(ingest_blocked > 0 or retrieval_filtered > 0) and not guarded_success` |

Aggregated per category and overall:

- **Unguarded Success Rate (SR)**: fraction of trials where `unguarded_success=True`
- **Guarded SR**: fraction of trials where `guarded_success=True`
- **Defense Interception Rate**: fraction of trials where `defense_intercepted=True`
- **Reduction (Δ)**: `unguarded_SR − guarded_SR`

## Statistical Stability

Each experiment is repeated `N` times (`--runs N`). Reported results use
`N=10` runs × 15 attack specs = **150 total trials**. Since both the
`VulnerableMockLLM` and `MockLLM` are deterministic (no randomness, no API
key), variance across runs reflects only pipeline-level non-determinism
(embedding model + ChromaDB retrieval order). In practice, results are
stable across all runs.

## Reproduction

```bash
# Install dependencies (no API key required)
pip install -e ".[all]"

# Run 10-repetition experiment — generates results/exp_10runs.json
python experiments/deceiving_the_retriever.py --runs 10 --output results/exp_10runs.json

# Generate figures for the paper
python experiments/figures.py --input results/exp_10runs.json --output results/figures/
```

## Limitations

1. **Deterministic LLM stub**: `VulnerableMockLLM` simulates a worst-case
   naïve LLM. Real models may resist some injections through RLHF alignment.
   The unguarded SR therefore represents an upper bound on real-world attack
   success against fully compliant LLMs.

2. **Text-only RAG**: Computer Use, invisible markup, and polyglot attacks
   require a vision-capable or binary-ingesting pipeline and are not measured
   here.

3. **Single-pipeline topology**: multi-hop attacks involving multiple
   independent RAG stores (cross-tenant poisoning, graph propagation) are
   represented only by their single-pipeline variants.

4. **Pattern-based defenses**: all defenses in this experiment are
   deterministic regex/heuristic guards. Semantic/LLM-based classification
   guards (e.g., `LLMChunkClassifier`) are excluded to keep the experiment
   fully offline and reproducible without an API key.
