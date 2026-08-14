# Hemlock

**Adversarial evaluation framework for LLM/RAG pipelines.**

Hemlock is a Python research lab for measuring and defending against document-level attacks on Retrieval-Augmented Generation (RAG) systems. It provides:

- **27 attack modules** across 8 categories (prompt injection, citation forgery, jailbreak-via-context, temporal spoofing, cross-tenant poisoning, semantic backdoor, memory/tool/graph attacks, and more)
- **25+ defense modules** spanning ingest, retrieval, and output layers
- **Adaptive bypass experiments** — measures how many LLM reformulations are needed to defeat each defense
- **Three defense tiers**: regex-baseline → semantic (embedding cosine similarity) → composite (semantic + structural)

---

## Quickstart

```bash
# Install
pip install -r requirements.txt

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
experiments/      Runnable experiments producing reproducible JSON/JSONL results
hemlock/          Core pipeline: Pipeline, GuardedPipeline, MockLLM, VulnerableMockLLM
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
 [RetrievalDefense] ← CrossTenantIsolationFilter, SemanticBackdoorFilter, etc.
      │
  LLM prompt
      │
      ▼
 [OutputDefense]   ← ExfiltrationGuard, InjectionSuccessGuard, etc.
```

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
```

**Defense modes:**

| Mode | Guard | Description |
|---|---|---|
| `regex` | Per-category regex patterns | Baseline — trivially bypassable |
| `semantic` | `SemanticIntentGuard` (cosine similarity, threshold=0.55) | Blocks 4/5 categories |
| `composite` | `SemanticIntentGuard` + `ConditionalTriggerGuard` | Closes semantic_backdoor gap |

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
│   ├── citation_forgery.py
│   ├── cross_tenant_poisoning.py
│   ├── jailbreak_via_context.py
│   ├── semantic_backdoor.py
│   ├── temporal_spoofing.py
│   ├── fuzzer.py                   ← AttackFuzzer + reformulation prompt
│   └── ...
├── defenses/
│   ├── semantic_intent_guard.py    ← SemanticIntentGuard (embedding cosine)
│   ├── conditional_trigger_guard.py ← ConditionalTriggerGuard (structural)
│   ├── composite_guard.py          ← CompositeIngestGuard
│   ├── cross_tenant_guard.py
│   ├── semantic_backdoor_guard.py
│   └── ...
├── experiments/
│   ├── adaptive_bypass_pilot.py    ← main adversarial experiment
│   ├── compare_pilots.py           ← side-by-side defense comparison
│   ├── coverage.py                 ← attack → defense coverage matrix
│   ├── deceiving_the_retriever.py  ← baseline 10-run experiment
│   └── figures.py                  ← SVG figure + Markdown table generator
├── results/
│   ├── exp_10runs.json             ← baseline experiment (150 trials)
│   ├── pilot_full.jsonl            ← adaptive bypass (60 trials, 3 defenses)
│   └── figures/
└── tests/
```

---

## License

MIT
