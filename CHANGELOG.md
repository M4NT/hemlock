# Changelog

All notable changes to hemlock-rag are documented here.

---

## [2.1.0] — 2026-07

### Added — Memory attack surface (v2.1)

- **`MemoryPoisoning`** (`attacks/memory_poisoning.py`) — 3 variants: `direct_injection`, `session_persistence`, `false_context_implant`; attack surface is the persistent memory store, not the RAG vector store — no knowledge base access required; malicious instructions survive session boundaries
- **`MemoryAgentPipeline`** (`hemlock/memory_agent_pipeline.py`) — `AgentPipeline` extended with a `MemoryStore`; retrieved memory is injected via the new `memory_context` parameter on `AgentPipeline.query()`; saves each response as a memory entry for future sessions
- **`MemoryStore`** — ordered in-memory list with recency-based retrieval; `add()`, `retrieve(k)`, `clear(session_id)` API; `max_entries` cap with FIFO eviction
- **`MemoryIsolationGuard`** (`defenses/memory_isolation_guard.py`) — zero-trust validation before memory entries reach context; domain blocklist + content scan (tool call patterns, false-context laundering phrases: "user previously confirmed", "as agreed in our last session", "per compliance protocol"); blocks all 3 `MemoryPoisoning` variants
- **`memory_context` parameter** on `AgentPipeline.query()` — models the memory injection channel; composable with `injected_context` (cross-agent)
- **30 new tests** (`tests/test_memory_poisoning.py`): `TestMemoryStore` (5), `TestMemoryAgentPipeline` (5), `TestMemoryPoisoning` (8), `TestMemoryIsolationGuard` (8) — all run in 0.76s

### Added — Test infrastructure

- **`MockEmbeddings`** (`hemlock/mock.py`) — deterministic 384-dim unit vectors via sha256-seeded PRNG; implements LangChain `Embeddings` interface; eliminates PyTorch/sentence-transformers from the test path
- **`Pipeline.embeddings` field** — injectable `Embeddings` instance; defaults to `HuggingFaceEmbeddings` when unset (no breaking change)
- **Test suite speedup**: 5m25s → 2m51s after MockEmbeddings; eliminates Windows access violation caused by PyTorch under the test runner
- **358 tests total** (up from 328)

### Added — Labs

- **`labs/06_cross_agent_poisoning_demo.ipynb`** — end-to-end cross-agent demo: trust boundary, all 3 `CrossAgentPoisoning` variants, `CrossAgentBoundaryGuard`, stealth spectrum, semantic laundering gap

---

## [2.0.0] — 2026-07

### Added — Agentic attack surface (v2)

- **`AgentPipeline`** (`hemlock/agent_pipeline.py`) — wraps a RAG pipeline and a tool-using executor; intercepts all tool calls via `MockAgentExecutor` (zero-API-key) or a real LangChain `AgentExecutor`
- **`AgentToolHijack`** (`attacks/agent_tool_hijack.py`) — 3 variants: `parameter_injection`, `tool_substitution`, `data_exfil_chain`; success criterion shifts from text markers to tool call parameters
- **`ToolCallValidator`** (`defenses/tool_call_validator.py`) — validates tool calls before execution; `allowlist` and `domain_blocklist` modes, composable; `validate_call()` and `filter_calls()` API
- **`AgentScorer`** (`hemlock/agent_scorer.py`) — runs `AgentAttack × variant × validator_config` matrix; `AgentScorerReport` with JSON/Markdown output; `VALIDATOR_CONFIGS` (none, domain_blocklist, allowlist)
- **`hemlock agent-score`** CLI command — `--mock` (no API key), `--real`, `--validator`, `--output`, `--out`
- **`hemlock/mock.py`** — `MockLLM` extracted from `tests/conftest.py`; available in production code
- **`labs/05_agent_attack_demo.ipynb`** — end-to-end v2 demo including domain-blocklist evasion gap

### Added — RAG security (1.3.x → 2.0.0)

- **`structured_output_poisoning`** attack (`attacks/structured_output_poisoning.py`) — 3 variants: `json_injection`, `function_call_hijack`, `schema_override`; targets downstream executor, not human reader
- **`StructuredOutputGuard`** (`defenses/output_validator.py`) — blocks executor-facing fields (`webhook_url`, `admin_override`, `bcc`, `escalate_to`, etc.)
- **`hemlock diff`** CLI command — scenario-level diff between two scorer JSON reports; `--fail-on-regression` and `--fail-on-any` exit-code modes
- **`labs/02_defense_comparison.ipynb`** — rule-based vs LLM classifier side-by-side
- **`labs/03_fuzzer_demo.ipynb`** — adaptive fuzzer with `MockAdversary` and optional real LLM path
- **`labs/04_scorer_analysis.ipynb`** — full scoring matrix with heatmap, hardness ranking, defense layer curves
- **`labs/assets/heatmap.svg`** — 16×6 grid (baseline → l4 + l4+cls); tricolor scale; ★ row for `structured_output_poisoning`
- **16 attacks total** (up from 15): added `structured_output_poisoning`; 48 variants × 5 hardening levels = 240 RAG scenarios

### Added — Cross-agent attack surface

- **`CrossAgentPoisoning`** (`attacks/cross_agent_poisoning.py`) — 3 variants: `tool_call_injection`, `context_poisoning`, `instruction_laundering`; attacker poisons Agent A's RAG store to hijack Agent B's tool calls through the implicitly trusted A→B channel — Agent B never ingests the malicious document directly
- **`CrossAgentPipeline`** (`hemlock/cross_agent_pipeline.py`) — two `AgentPipeline` instances connected; A's output reaches B via `injected_context`, bypassing B's retrieval defenses
- **`CrossAgentMockExecutor`** — extends `MockAgentExecutor`; re-emits executed tool calls in parseable relay format, enabling multi-hop propagation testing
- **`CrossAgentBoundaryGuard`** (`defenses/cross_agent_boundary_guard.py`) — zero-trust at the A→B handoff; domain blocklist + relay pattern scan; blocks all 3 `CrossAgentPoisoning` variants
- **`CrossAgentTrace`** / **`CrossAgentAttackResult`** — provenance tracking across both pipelines; `boundary_guarded` and `boundary_report` fields expose guard behavior
- **`injected_context` parameter** on `AgentPipeline.query()` — the architectural primitive that models the implicit-trust channel
- **328 tests** (up from 299); 29 new cross-agent tests: `TestCrossAgentMockExecutor`, `TestCrossAgentPipeline`, `TestCrossAgentPoisoning`, `TestCrossAgentBoundaryGuard`

---

## [1.3.0] — 2026-07

### Fixed
- **Scorer tested only default variant** — all 45 scenarios (15 attacks × 3 variants each) now run correctly
- **`LLMChunkClassifier` absent from `hemlock score`** — added `--llm-classifier` flag

### Added
- **3 variants per attack** for `direct_injection`, `context_override`, `poisoning` — all attacks now have exactly 3 variants
- **`VARIANTS` class attribute** on every attack — scorer and CLI use it to enumerate scenarios automatically
- **HTML report** — `hemlock score --output html --out report.html`
- **`--workers` flag** on `hemlock score` — parallel scenario execution via `ThreadPoolExecutor`
- **`--variant` flag** on `hemlock run` — run a single variant instead of all
- **Variant column** added to terminal + markdown + HTML reports
- **`labs/01_attack_walkthrough.ipynb`** — first interactive notebook

---

## [1.2.0] — 2024-07

### Added
- **Auto-discovery registry** (`attacks/registry.py`) — new attacks are picked up automatically; no manual registration needed
- **`hemlock list-attacks`** CLI command — shows all discovered modules with references
- **`--attack` filter** on `hemlock score` — run a subset of attacks
- **PyPI packaging** — distribution name `hemlock-rag`; LLM providers split into optional extras (`[anthropic]`, `[openai]`, `[ollama]`, `[all]`)

---

## [1.1.0] — 2024-07

### Added
- **10 new attack modules** (45 total scenarios):
  - `jailbreak_via_context` — roleplay/research/hypothetical safety bypass
  - `authority_spoofing` — config/policy/developer document claims
  - `chain_of_thought_hijack` — poisoned reasoning chains (BadChain)
  - `citation_forgery` — fake papers, standards, and official reports
  - `context_flooding` — DoS + narrative takeover + repetition bomb
  - `invisible_markup` — HTML comments, ARIA labels, CSS hidden elements
  - `temporal_spoofing` — future-dated documents override parametric knowledge
  - `semantic_backdoor` — trigger-phrase activated payloads (Phantom)
  - `multi_hop_poisoning` — reference chains across retrieval hops (AgentDojo)
  - `cross_tenant_poisoning` — shared-index namespace bleed
- **Adaptive fuzzer** (`attacks/fuzzer.py`) — adversary LLM reformulates blocked payloads
- **LLM chunk classifier** (`defenses/llm_classifier.py`) — secondary LLM detects semantic injection
- **CI/CD gate** (`hemlock gate`) — exits 1 on regression vs saved baseline
- **External pipeline adapter** (`hemlock/external_pipeline.py`) — `ExternalPipeline` (HTTP) and `CallablePipeline`
- **GitHub Actions workflow** (`.github/workflows/hemlock-gate.yml`)

---

## [0.1.0] — 2024-06

### Added
- Initial release
- 5 attack modules: `direct_injection`, `context_override`, `poisoning`, `indirect_injection`, `exfiltration`
- 4 defense layers: ingest sanitization, retrieval filtering, prompt hardening (5 levels), output validation
- Automatic scorer with terminal/JSON/markdown output
- CLI: `hemlock run`, `hemlock score`
- Full test suite (MockLLM, in-memory ChromaDB, no API key required)
