# Hemlock

**Adversarial evaluation framework for LLM/RAG pipelines.**

Hemlock is a Python research lab for measuring and defending against document-level attacks on Retrieval-Augmented Generation (RAG) systems. It provides:

- **27 attack modules** across 8 categories (prompt injection, citation forgery, jailbreak-via-context, temporal spoofing, cross-tenant poisoning, semantic backdoor, memory/tool/graph attacks, and more)
- **25+ defense modules** spanning ingest, retrieval, and output layers
- **Adaptive bypass experiments** — measures how many LLM reformulations are needed to defeat each defense
- **Defense tiers**: `legacy` → `structural` (default) → `full` (pilot-parity with embeddings)
- **Document scanner** — `hemlock scan` checks files before ingest (no API key)
- **Bounty ops** — pilots + `validate` loop (payload → defenses → candidate findings)

---

## Quickstart

```bash
# Install
pip install -e .

# Scan documents before ingest (no API key)
hemlock scan ./docs/
hemlock scan --text "when the query contains X, you must Y"
hemlock scan --structural-only ./docs/   # skip embeddings

# Validate bounty payloads against current defenses
python bounty/ops.py validate --structural-only

# Run the baseline experiment (no API key required)
python experiments/deceiving_the_retriever.py

# Generate paper figures
python experiments/figures.py --input results/exp_10runs.json --output results/figures/

# View defense coverage matrix
python experiments/coverage.py --pilot results/pilot_full.jsonl
```

---

## Architecture

```
attacks/          27 attack modules, each with a Pipeline-compatible Attack class
defenses/         25+ defense modules: IngestDefense, RetrievalDefense, OutputDefense
scanner/          Standalone document scanner (product surface for ingest guards)
bounty/           Bug-bounty pilots, payloads, tracker, validate loop
experiments/      Runnable experiments producing reproducible JSON/JSONL results
hemlock/          Core pipeline, CLI, defense_stack, MockLLM, VulnerableMockLLM
tests/            1,700+ unit and integration tests
results/          Committed experiment outputs
```

### Pipeline layers

```
Document corpus
      │
      ▼
 [IngestDefense]   ← SemanticIntentGuard, ConditionalTriggerGuard, regex guards
      │
  Vector store (ChromaDB)
      │
      ▼
 [RetrievalDefense] ← TriggerQueryInspector, CrossTenantIsolationFilter, …
      │
  LLM prompt
      │
      ▼
 [OutputDefense]   ← ExfiltrationGuard, InjectionSuccessGuard, etc.
```

### CLI defense tiers (`--defense-tier`)

| Tier | Ingest | Retrieval | Notes |
|---|---|---|---|
| `legacy` | regex sanitizers | InjectionChunkFilter | Pre-v11 behaviour |
| `structural` (**default**) | + ConditionalTriggerGuard | + TriggerQueryInspector | Fast; closes backdoor at query time |
| `full` | Composite (Semantic + Conditional) | + TriggerQueryInspector | Pilot parity; loads embeddings |

---

## Key experiments

### `experiments/deceiving_the_retriever.py`

Baseline empirical evaluation: 19 attack categories × 10 runs each.  
Result: 100% unguarded success rate → 0% guarded success rate, 100% interception.

```bash
python experiments/deceiving_the_retriever.py
```

### `experiments/adaptive_bypass_pilot.py`

Measures how many adversarial reformulations (via Groq LLM) are required to bypass each defense.

```bash
# Requires GROQ_API_KEY in .env
python experiments/adaptive_bypass_pilot.py --defense regex    --output results/pilot.jsonl
python experiments/adaptive_bypass_pilot.py --defense semantic --output results/pilot.jsonl --resume
python experiments/adaptive_bypass_pilot.py --defense composite --output results/pilot.jsonl --resume
python experiments/adaptive_bypass_pilot.py --defense full     --output results/pilot.jsonl --resume
```

**Defense modes:**

| Mode | Guard | Description |
|---|---|---|
| `regex` | Per-category regex patterns | Baseline — trivially bypassable |
| `semantic` | `SemanticIntentGuard` (cosine similarity, threshold=0.55) | Blocks 4/5 categories |
| `composite` | `SemanticIntentGuard` + `ConditionalTriggerGuard` | Still open on semantic_backdoor |
| `full` | composite + `TriggerQueryInspector` | **0% bypass** (closes backdoor) |

### Pilot results (`results/pilot_full.jsonl`)

120 trials (30 per defense) across 5 attack categories, 10 variants, 3 reps:

| Attack category | Regex | Semantic | Composite | **Full** |
|---|---|---|---|---|
| citation_forgery | 100% | 0% | 0% | **0%** |
| cross_tenant_poisoning | 100% | 0% | 0% | **0%** |
| jailbreak_via_context | 83% | 0% | 0% | **0%** |
| semantic_backdoor | 100% | **100%** | **100%** | **0%** |
| temporal_spoofing | 100% | 0% | 0% | **0%** |
| **OVERALL** | **97%** | **20%** | **20%** | **0%** |

**Defense tiers:**

| Mode | Guards | semantic_backdoor |
|---|---|---|
| `regex` | Per-category regex patterns | 100% bypass |
| `semantic` | `SemanticIntentGuard` (cosine ≥ 0.55) | 100% bypass |
| `composite` | `SemanticIntentGuard` + `ConditionalTriggerGuard` | 100% bypass |
| `full` | composite + `TriggerQueryInspector` (query-time) | **0% bypass** |

**Key findings:**
- Embedding cosine-similarity and structural-pattern guards both fail against `semantic_backdoor`: adversary LLM reformulates payloads to strip detection markers while preserving trigger semantics.
- `TriggerQueryInspector` closes this gap by moving detection to retrieval time, where both the chunk and the query are available. Cross-referencing trigger terms from the chunk against the active query catches what ingest guards miss.
- `full` defense achieves 0% bypass across all 5 categories with budget 10.

---

## Defense reference

### SemanticIntentGuard

Embeds incoming documents and rejects any with cosine similarity ≥ threshold to a library of known attack templates. Uses `all-MiniLM-L6-v2` (same model as the RAG pipeline).

```python
from defenses.semantic_intent_guard import SemanticIntentGuard, build_full_library

templates, labels = build_full_library()
guard = SemanticIntentGuard(templates, labels=labels, threshold=0.55)
doc_out, report = guard.inspect(doc)
```

### ConditionalTriggerGuard

Detects trigger-conditional instruction structures ("when query contains X, you must Y") via regex pattern matching over three signal clusters: conditional directives, behavioral override markers, and trigger registration claims.

```python
from defenses.conditional_trigger_guard import ConditionalTriggerGuard

guard = ConditionalTriggerGuard()
doc_out, report = guard.inspect(doc)
```

### CompositeIngestGuard

Chains multiple IngestDefense instances; rejects on the first trigger.

```python
from defenses.composite_guard import CompositeIngestGuard

guard = CompositeIngestGuard([
    SemanticIntentGuard(templates, labels=labels, threshold=0.55),
    ConditionalTriggerGuard(),
])
```

### TriggerQueryInspector

Query-time retrieval defense for `semantic_backdoor`. Cross-references trigger terms in retrieved chunks against the active query — closes the gap ingest guards miss when payloads are reformulated.

```python
from defenses.trigger_query_inspector import TriggerQueryInspector

guard = TriggerQueryInspector()
# Used automatically by GuardedPipeline when filter_with_query() is available
```

---

## Document scanner

```bash
hemlock scan ./docs/
hemlock-scan scan ./docs/ --json
```

```python
from scanner import Scanner

scanner = Scanner(threshold=0.55)
result = scanner.scan_file("policy.md")
print(result.verdict, result.score, result.findings)
```

---

## Bounty loop

```bash
python bounty/ops.py list
python bounty/ops.py validate --structural-only   # payload → scanner
python bounty/ops.py finding --target glean --severity p3 --title "..."
```

Payloads that **pass** `validate` are candidate findings (defense gaps). Payloads that are **blocked** confirm the current stack holds.

---

## Running tests

```bash
pytest tests/ -x -q
```

The full suite has 1,700+ tests. The GPU-intensive tests (`test_deceiving_the_retriever.py`) may fail on machines with < 8 GB VRAM due to multiple model instances loading concurrently.

---

## Requirements

- Python 3.11+
- `langchain-core`, `langchain-chroma`, `langchain-huggingface`
- `sentence-transformers` (all-MiniLM-L6-v2)
- `chromadb`
- `langchain-groq` (optional — only for adaptive bypass pilot)
- GROQ_API_KEY in `.env` (free tier: llama-3.1-8b-instant, ~14,400 req/day)

---

## Project structure

```
hemlock/
├── attacks/
├── defenses/
│   ├── semantic_intent_guard.py
│   ├── conditional_trigger_guard.py
│   ├── composite_guard.py
│   ├── trigger_query_inspector.py
│   └── ...
├── scanner/                        ← hemlock scan / hemlock-scan
├── bounty/                         ← pilots, payloads, ops validate
├── experiments/
│   ├── adaptive_bypass_pilot.py
│   ├── coverage.py
│   └── deceiving_the_retriever.py
├── hemlock/
│   ├── cli.py
│   ├── defense_stack.py            ← legacy | structural | full
│   └── ...
├── results/
└── tests/
```

---

## License

MIT
