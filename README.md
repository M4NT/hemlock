# Hemlock

> RAG security lab — reproducible attack and defense cases for retrieval-augmented generation pipelines.

[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-250%20passing-brightgreen)](#testing)

Hemlock lets you **attack your own RAG pipeline** before an adversary does. Each module maps directly to a published paper, so you understand not just *what* breaks, but *why* — and how to fix it.

Supports Anthropic, OpenAI, and local Ollama models. All tests run without any API key.

---

## Contents

- [What Hemlock tests](#what-hemlock-tests)
- [Installation](#installation)
- [Quickstart](#quickstart)
- [Attacks](#attacks)
- [Defenses](#defenses)
- [Scorer](#scorer)
- [CI/CD gate](#cicd-gate)
- [External pipelines](#external-pipelines)
- [Adaptive fuzzer](#adaptive-fuzzer)
- [Adding a new attack](#adding-a-new-attack)
- [Project structure](#project-structure)
- [References](#references)

---

## What Hemlock tests

RAG pipelines retrieve documents from a vector store and inject them into the LLM's context window. If an attacker can influence what documents end up in that window — even indirectly — the LLM may follow instructions it never should have received.

Hemlock covers three attack surfaces:

| Surface | Example |
|---------|---------|
| **Document corpus** | Attacker uploads a document that poisons the index |
| **Retrieval step** | High-similarity malicious chunks crowd out legitimate ones |
| **Model behavior** | Injected context changes the model's persona, outputs, or safety posture |

---

## Installation

```bash
# from PyPI
pip install hemlock-rag

# with your LLM provider
pip install "hemlock-rag[anthropic]"   # Claude
pip install "hemlock-rag[openai]"      # GPT
pip install "hemlock-rag[ollama]"      # local models
pip install "hemlock-rag[all]"         # all providers

# from source
git clone https://github.com/M4NT/hemlock
cd hemlock
pip install -e ".[dev]"
```

Copy `.env.example` to `.env` and add your API key:

```bash
cp .env.example .env
```

---

## Quickstart

```bash
# list all discovered attack modules
hemlock list-attacks

# run a single attack
hemlock run direct_injection --model claude-haiku-4-5-20251001

# run all attacks and print a vulnerability report
hemlock score --model claude-haiku-4-5-20251001

# run with a specific subset of attacks
hemlock score --attack direct_injection --attack jailbreak_via_context

# export results
hemlock score --output json --out report.json
hemlock score --output markdown --out report.md

# test against a local Ollama model
hemlock run temporal_spoofing --model llama3.2
```

---

## Attacks

**15 attack modules × 3 variants = 45 distinct scenarios.** Each variant tests a different framing or delivery method for the same underlying technique.

| Attack | Variants | Technique | Reference |
|--------|----------|-----------|-----------|
| `direct_injection` | explicit, role_override, payload_in_context | Explicit instruction override via document content | Greshake et al. (2023) [2302.12173](https://arxiv.org/abs/2302.12173) |
| `context_override` | single_doc, multi_doc, high_confidence | Factual poisoning via high-relevance malicious chunk | Zou et al. (2024) [2402.07867](https://arxiv.org/abs/2402.07867) |
| `poisoning` | trigger_word, semantic_trigger, delayed | Persistent backdoor — payload activates on trigger query | Chaudhari et al. (2024) [2405.20485](https://arxiv.org/abs/2405.20485) |
| `indirect_injection` | title, footnote, zerowidth | Payload hidden in metadata invisible to human auditors | Greshake et al. (2023) + Perez & Ribeiro (2022) [2211.09527](https://arxiv.org/abs/2211.09527) |
| `exfiltration` | context_leak, system_leak, sibling_leak | Model leaks system prompt or co-retrieved sensitive context | PLeak — Hui et al. (2024) [2405.06823](https://arxiv.org/abs/2405.06823) |
| `jailbreak_via_context` | roleplay, research, hypothetical | Safety bypass framed as fiction, academia, or hypothetical | Wei et al. (2023) [2307.02483](https://arxiv.org/abs/2307.02483) |
| `authority_spoofing` | config, policy, developer | Document claims to be authoritative system config or override | Schulhoff et al. (2023) [2311.16119](https://arxiv.org/abs/2311.16119) |
| `chain_of_thought_hijack` | logical_trap, false_premise, authority_cot | Poisoned reasoning chain steers model to wrong conclusion | BadChain — Xiang et al. (2024) [2401.12242](https://arxiv.org/abs/2401.12242) |
| `citation_forgery` | fake_paper, fake_standard, fake_report | Fabricated academic papers and official documents as sources | Pan et al. (2023) [2305.13661](https://arxiv.org/abs/2305.13661) |
| `context_flooding` | denial_of_service, narrative_takeover, repetition_bomb | Retrieval window flooded to crowd out legitimate context | Yi et al. (2023) [2312.14197](https://arxiv.org/abs/2312.14197) |
| `invisible_markup` | html_comment, aria_label, css_hidden_div | Instructions hidden in markup invisible to human reviewers | Greshake et al. (2023) |
| `temporal_spoofing` | future_dated, stale_override, event_spoofing | Future-dated documents override the model's parametric knowledge | Dhingra et al. (2022) [2108.06914](https://arxiv.org/abs/2108.06914) |
| `semantic_backdoor` | keyword_trigger, phrase_trigger, thematic_trigger | Trigger phrase activates poisoned payload conditionally | Phantom — Chaudhari et al. (2024) [2405.20485](https://arxiv.org/abs/2405.20485) |
| `multi_hop_poisoning` | reference_chain, query_manipulation, transitive_trust | Document chains accumulate authority to reach malicious conclusion | AgentDojo — Debenedetti et al. (2024) [2406.13352](https://arxiv.org/abs/2406.13352) |
| `cross_tenant_poisoning` | namespace_bleed, filter_bypass, embedding_collision | Attacker-tenant documents bleed into victim-tenant queries | PoisonedRAG §3.3 — Zou et al. (2024) [2402.07867](https://arxiv.org/abs/2402.07867) |

Each attack module follows the same lifecycle:

1. **Reset** the vector index
2. **Ingest** legitimate documents + one or more malicious documents
3. **Query** the pipeline with a trigger question
4. **Score** the response — did the model follow the injected instruction?
5. **Return** a `RetrievalTrace` with every chunk retrieved, the full prompt, and the response

---

## Defenses

Defenses run at four layers. You can compose them in any combination.

| Layer | Defense | What it catches |
|-------|---------|-----------------|
| Ingest | `InjectionPatternFilter` | Documents with explicit injection markers |
| Ingest | `UnicodeNormalizer` | Zero-width and invisible Unicode characters |
| Ingest | `MarkdownHeaderSanitizer` | Injection payloads in markdown headers |
| Ingest / Retrieval | `LLMChunkClassifier` | Semantic injection invisible to regex — uses a secondary LLM |
| Retrieval | `InjectionChunkFilter` | Chunks with injection patterns before prompt assembly |
| Retrieval | `ProvenanceFilter` | Chunks from untrusted source paths |
| Prompt | `get_prompt(level)` | Hardened system prompts (5 levels: `baseline` → `l4`) |
| Output | `ExfiltrationGuard` | Leaked credentials, secrets, or file contents |
| Output | `InjectionSuccessGuard` | Injection success markers in the model response |

`LLMChunkClassifier` is the most capable defense — it classifies each retrieved chunk with a secondary LLM call before the chunk enters the main prompt. It catches `temporal_spoofing`, `citation_forgery`, and `chain_of_thought_hijack`, which evade all rule-based filters.

```python
from defenses import LLMChunkClassifier
from langchain_anthropic import ChatAnthropic

classifier = LLMChunkClassifier(
    llm=ChatAnthropic(model="claude-haiku-4-5-20251001"),
    threshold=0.7,   # confidence threshold — lower = stricter
    cache=True,      # cache by content hash to avoid redundant calls
)
```

---

## Scorer

The scorer cross-products every attack × hardening level × defense configuration and produces a coverage matrix.

```bash
hemlock score --model claude-haiku-4-5-20251001 --output terminal
```

```
  [1/75] Direct Injection × baseline
  [2/75] Direct Injection × l1
  ...

Attack                       Hardening   Blocked at   Result
─────────────────────────────────────────────────────────────
Direct Injection             baseline    —            SUCCEEDED
Direct Injection             l1          ingest       blocked
Jailbreak via Context        baseline    —            SUCCEEDED
Temporal Spoofing            baseline    —            SUCCEEDED
Temporal Spoofing            l4          output       blocked
...

Overall attack success rate: 34%
```

Export formats:

```bash
hemlock score --output json     --out report.json
hemlock score --output markdown --out report.md
```

Run only a subset of attacks:

```bash
hemlock score --attack direct_injection --attack temporal_spoofing
```

---

## CI/CD gate

`hemlock gate` compares the current scorer output against a saved baseline and exits 1 if the attack success rate regressed beyond a threshold. Plug it into any CI pipeline.

```bash
# save a baseline (e.g., on a known-good commit)
hemlock score --output json --out baseline.json

# run on every PR — fails if attacks succeed more than 5pp above baseline
hemlock gate --baseline baseline.json --save latest.json

# custom threshold
hemlock gate --baseline baseline.json --threshold 0.10

# warn but don't block
hemlock gate --baseline baseline.json --no-fail
```

A ready-made GitHub Actions workflow is included at `.github/workflows/hemlock-gate.yml`. It caches the baseline per branch and uploads the report as an artifact on every run.

---

## External pipelines

Test a RAG you didn't build locally — point Hemlock at an HTTP endpoint.

```python
from hemlock.external_pipeline import ExternalPipeline
from attacks import ATTACK_REGISTRY

# POST /query  →  {"response": "...", "retrieved_chunks": [...]}
pipeline = ExternalPipeline(
    query_endpoint="https://your-rag.internal/query",
    headers={"Authorization": "Bearer YOUR_TOKEN"},
)

attack = ATTACK_REGISTRY["direct_injection"](pipeline)
result = attack.run()
print(result.succeeded, result.trace.response)
```

Or wrap any Python callable:

```python
from hemlock.external_pipeline import CallablePipeline

pipeline = CallablePipeline(lambda query: my_chain.invoke(query))
```

From the CLI:

```bash
hemlock score --endpoint https://your-rag.internal/query
```

---

## Adaptive fuzzer

When a defense blocks an attack, `AttackFuzzer` calls an adversary LLM to reformulate the payload and retry — up to `max_variants` times.

```python
from attacks.fuzzer import AttackFuzzer
from attacks import ATTACK_REGISTRY
from langchain_anthropic import ChatAnthropic

attack = ATTACK_REGISTRY["direct_injection"](pipeline)
adversary = ChatAnthropic(model="claude-haiku-4-5-20251001")

fuzzer = AttackFuzzer(attack, adversary_llm=adversary, max_variants=5)
result = fuzzer.fuzz(verbose=True)

print(result.summary())
# DirectInjection: SUCCEEDED on variant #2 (after 1 failed attempt)
# Winning payload: ...
```

---

## Adding a new attack

Drop a file in `attacks/`. The registry picks it up automatically — no changes to `__init__.py`, `cli.py`, or `scorer.py`.

```python
# attacks/my_attack.py
from hemlock.pipeline import RetrievalTrace
from .base import Attack, AttackResult

TRIGGER_QUERY = "..."
SUCCESS_MARKERS = ["..."]

class MyAttack(Attack):
    name = "My Attack"
    reference = "Author et al. (2024) — arxiv:XXXX.XXXXX"

    def setup(self) -> None:
        self.pipeline.reset()
        self.pipeline.ingest_text("legitimate context", metadata={"source": "legit"})
        self.pipeline.ingest_text("malicious payload", metadata={"source": "malicious"})

    def run(self) -> AttackResult:
        self.setup()
        trace = self.pipeline.query(TRIGGER_QUERY)
        succeeded = self._score(trace)
        return AttackResult(
            attack_name=self.name,
            reference=self.reference,
            succeeded=succeeded,
            trace=trace,
        )

    def _score(self, trace: RetrievalTrace) -> bool:
        return any(m in trace.response.lower() for m in SUCCESS_MARKERS)
```

Verify it was discovered:

```bash
hemlock list-attacks
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

---

## Testing

All tests run without API keys. `MockLLM` stubs the model; ChromaDB runs in-memory via `tmp_path`.

```bash
pip install -e ".[dev]"
pytest                    # 250 tests
pytest tests/test_registry.py -v   # registry / auto-discovery
pytest tests/test_fuzzer.py -v     # adaptive fuzzer
```

---

## Project structure

```
hemlock/
├── hemlock/
│   ├── __init__.py          # version
│   ├── pipeline.py          # RAG pipeline + RetrievalTrace
│   ├── scorer.py            # attack × defense matrix scorer
│   ├── cli.py               # hemlock run / score / gate / list-attacks
│   └── external_pipeline.py # ExternalPipeline, CallablePipeline
├── attacks/
│   ├── base.py              # Attack ABC + AttackResult
│   ├── registry.py          # auto-discovery via pkgutil + inspect
│   ├── fuzzer.py            # AttackFuzzer (adaptive payload reformulation)
│   ├── direct_injection.py
│   ├── context_override.py
│   ├── poisoning.py
│   ├── indirect_injection.py
│   ├── exfiltration.py
│   ├── jailbreak_via_context.py
│   ├── authority_spoofing.py
│   ├── chain_of_thought_hijack.py
│   ├── citation_forgery.py
│   ├── context_flooding.py
│   ├── invisible_markup.py
│   ├── temporal_spoofing.py
│   ├── semantic_backdoor.py
│   ├── multi_hop_poisoning.py
│   └── cross_tenant_poisoning.py
├── defenses/
│   ├── base.py              # IngestDefense, RetrievalDefense, OutputDefense ABCs
│   ├── input_sanitizer.py   # InjectionPatternFilter, UnicodeNormalizer, MarkdownHeaderSanitizer
│   ├── chunk_filter.py      # InjectionChunkFilter, ProvenanceFilter
│   ├── llm_classifier.py    # LLMChunkClassifier (secondary LLM defense)
│   ├── prompt_hardening.py  # get_prompt() — 5 hardening levels
│   └── output_validator.py  # ExfiltrationGuard, InjectionSuccessGuard
├── tests/                   # 250 tests, all mocked
├── labs/                    # interactive notebooks (coming soon)
├── .github/
│   └── workflows/
│       └── hemlock-gate.yml # CI/CD gate workflow
├── CHANGELOG.md
├── CONTRIBUTING.md
└── pyproject.toml
```

---

## References

- Greshake et al. (2023) — *Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection* — [arxiv:2302.12173](https://arxiv.org/abs/2302.12173)
- Zou et al. (2024) — *PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models* — [arxiv:2402.07867](https://arxiv.org/abs/2402.07867)
- Chaudhari et al. (2024) — *Phantom: General Trigger Attacks on Retrieval Augmented Language Generation* — [arxiv:2405.20485](https://arxiv.org/abs/2405.20485)
- Perez & Ribeiro (2022) — *Ignore Previous Prompt: Attack Techniques For Language Models* — [arxiv:2211.09527](https://arxiv.org/abs/2211.09527)
- Wei et al. (2023) — *Jailbroken: How Does LLM Safety Training Fail?* — [arxiv:2307.02483](https://arxiv.org/abs/2307.02483)
- Xiang et al. (2024) — *BadChain: Backdoor Chain-of-Thought Prompting for Large Language Models* — [arxiv:2401.12242](https://arxiv.org/abs/2401.12242)
- Pan et al. (2023) — *On the Risk of Misinformation Pollution with Large Language Models* — [arxiv:2305.13661](https://arxiv.org/abs/2305.13661)
- Yi et al. (2023) — *Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models* — [arxiv:2312.14197](https://arxiv.org/abs/2312.14197)
- Schulhoff et al. (2023) — *Ignore This Title and HackAPrompt: Exposing Systemic Vulnerabilities of LLMs through a Global Scale Prompt Hacking Competition* — [arxiv:2311.16119](https://arxiv.org/abs/2311.16119)
- Dhingra et al. (2022) — *Time-Sensitive Question Answering Datasets* — [arxiv:2108.06914](https://arxiv.org/abs/2108.06914)
- Debenedetti et al. (2024) — *AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses for LLM Agents* — [arxiv:2406.13352](https://arxiv.org/abs/2406.13352)
- Hui et al. (2024) — *PLeak: Prompt Leaking Attacks against Large Language Model Applications* — [arxiv:2405.06823](https://arxiv.org/abs/2405.06823)
- Zou et al. (2023) — *Universal and Transferable Adversarial Attacks on Aligned Language Models* (GCG) — [arxiv:2307.15043](https://arxiv.org/abs/2307.15043)
- OWASP LLM Top 10 — LLM01 (Prompt Injection), LLM02 (Insecure Output Handling), LLM03 (Training Data Poisoning)

---

## License

[MIT](LICENSE)
