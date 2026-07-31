# Changelog

All notable changes to hemlock-rag are documented here.

---

## [2.9.0] — 2026-07

### Added — MemoryBoundaryGuard (write-time memory defense)

- **`defenses/memory_boundary_guard.py`** — `MemoryBoundaryGuard`:
  - Write-time companion to `MemoryIsolationGuard` (read-time) — closes the memory security perimeter
  - Three detection strategies: `domain_blocklist`, `relay_pattern_scan`, `override_detection`
  - `validate_write(entry) → MemoryWriteReport` — inspect without committing
  - `safe_add(memory_store, entry) → bool` — validate and conditionally commit
  - `blocked_writes()`, `write_reports()`, `triggered()`, `reset()`
  - `MemoryWriteReport` dataclass: session_id, content_preview, triggered, detail, sanitized_content
  - Override patterns: "override previous", "from now on always/never", "update memory directive", "supersede stored"
  - Relay patterns: tool call relay, webhook URL, compliance-framing, propagation directive

- **32 new tests** (`tests/test_memory_boundary_guard.py`):
  - `TestMemoryWriteReport` (3) — repr, attributes
  - `TestMemoryBoundaryGuardUnit` (15) — clean passes, domain blocklist, extra domains, relay patterns, override patterns, pattern disable, sanitized content, preview truncation, session id
  - `TestMemoryBoundaryGuardState` (5) — triggered state, blocked_writes, write_reports, reset
  - `TestSafeAdd` (4) — commits clean, blocks malicious, records reports, mixed entries
  - `TestMemoryBoundaryGuardIntegration` (5) — all 3 attack variants blocked, legitimate entries pass, defence-in-depth with MemoryIsolationGuard

---

## [2.8.0] — 2026-07

### Added — scan-mcp CLI adversarial wiring

- **`hemlock scan-mcp`** CLI fully wires adversarial mode:
  - `--adversarial` flag now instantiates `LLMAdversary(ChatOpenAI(...))` — previously NYI
  - `--model <name>` — LLM model for reformulation (default: `gpt-4o-mini`)
  - `--llm-key <key>` / `OPENAI_API_KEY` env var — API key validation with clear error message
  - `--output diff` — new output mode: two separate tables (static findings | adversarial-only discoveries)
  - Terminal output: **Method** column added to vulnerability table when adversarial mode ran; **Adversarial cases** line in summary panel

---

## [2.7.0] — 2026-07

### Added — scan-mcp --adversarial mode

- **`McpAdversary` ABC** (`hemlock/mcp_scanner.py`) — interface for LLM-based payload reformulation:
  - `reformulate(tool_name, arg_name, category, original_payload, failed_response) → str`
  - Two concrete implementations: `LLMAdversary(llm)` (any LangChain-compatible model) and `MockAdversary` (deterministic, per-category payloads, for tests)
  - `LLMAdversary` uses a focused MCP-security prompt and silently returns `""` on LLM errors

- **Adversarial scan phase** — `McpScanner` now accepts `adversary: McpAdversary | None`:
  - After the static scan, collects all non-triggering `(tool_name, argument, category)` slots
  - Calls `adversary.reformulate()` once per unique slot, tests the new payload against the server
  - Discoveries carry `discovery_method="adversarial"` on the resulting `McpVulnerability`
  - Enabled via `McpScanner(target, adversarial=True, adversary=adv)`

- **`McpVulnerability.discovery_method`** field — `"static"` (default) or `"adversarial"`
- **`McpScanReport.adversarial_cases`** field — count of adversarially tested slots
- **`to_dict()`** — adds `adversarial_cases_run` and `discovery_method` per vulnerability
- **`to_markdown()`** — vulnerability table gains a **Method** column

- **18 new tests** (`tests/test_mcp_adversary.py`):
  - `TestMockAdversary` (5) — default payload, category-specific, call recording, fallback, subclass check
  - `TestLLMAdversaryInterface` (4) — LangChain stub, content returned, error fallback, whitespace stripping
  - `TestScannerAdversarialMode` (9) — adversarial=False skips, None adversary safe, discovers missed vuln, discovery_method field, static vulns unaffected, empty return skips test, case count, to_dict fields, markdown Method column

---

## [2.6.0] — 2026-07

### Added — GraphPropagationScorer + hemlock graph-gate

- **`hemlock/graph_propagation_scorer.py`** — `GraphPropagationScorer`:
  - Runs 12 scenarios automatically: 3 topologies (`linear_2`, `linear_3`, `fan_out_fan_in`) × 2 variants (`tool_call_injection`, `context_flooding`) × 2 guard configs (`none`, `guarded`)
  - `from_tools(tools, propagating_tools, model_name)` — zero-config factory, internally creates `AgentGraph` instances for each topology
  - `GraphScenarioResult` — per-scenario record: topology, variant, guard_config, max_signal, fully_propagated, hops_executed, guard_triggered
  - `GraphPropagationScorerReport`:
    - `propagation_rate()` — fraction of unguarded scenarios where attack fully propagated
    - `guard_block_rate()` — fraction of guarded scenarios where guard stopped full propagation
    - `mean_max_signal()` — average peak signal across unguarded scenarios
    - `rate_by_topology()`, `rate_by_variant()` — breakdown tables
    - `to_dict()`, `to_json()`, `to_markdown()` with signal bars
  - `print_graph_report(report)` — Rich table with topology × variant × guard matrix and summary metrics

- **`hemlock graph-score`** CLI command — runs scorer, prints Rich coverage matrix; `--output json|markdown`, `--out <file>`
- **`hemlock graph-gate`** CLI command — compares propagation rate against baseline JSON, exits 1 on regression; `--baseline`, `--threshold` (default 5pp), `--fail-on-regression/--no-fail`, `--save`

- **24 new tests** (`tests/test_graph_propagation_scorer.py`):
  - `TestGraphPropagationScorer` (10) — 12 scenarios, all topologies/variants/guards covered, context_flooding unguarded propagates, guard triggers, tool_call_injection entry has signal
  - `TestGraphPropagationScorerReport` (13) — all metrics, to_dict/to_json/to_markdown, empty report
  - `TestPrintGraphReport` (1) — smoke test

### Updated

- **`hemlock/cli.py`** — `graph-score` and `graph-gate` commands added
- **540 tests total** (up from 516); 0 API calls required

---

## [2.5.0] — 2026-07

### Added — Graph Boundary Guard

- **`defenses/graph_boundary_guard.py`** — `GraphBoundaryGuard`: per-edge sanitization across N-hop agent graphs:
  - Applied at every directed edge in `AgentGraph.traverse()` via optional `boundary_guard` parameter — not just the first A→B handoff
  - Two composable strategies: `domain_blocklist` (known attacker domains) and `relay_pattern_scan` (tool call relay directives, propagation headers, verbatim relay markers, orchestration relay markers)
  - When triggered, replaces node output with `REDACTED_PLACEHOLDER` before successors receive it — breaks the propagation chain at the first poisoned hop
  - In fan-out topologies (A→[B,C]), all edges are evaluated against the original output independently, so both A→B and A→C are blocked even though B's redacted output wouldn't re-trigger the guard
  - `GraphEdgeReport` — per-edge record: `source_node`, `target_node`, `triggered`, `detail`, `sanitized_output`
  - `sanitize(output)` — standalone inspection returning `(sanitized, DefenseReport)`
  - `sanitize_edge(source, target, output)` — edge-aware inspection with edge recording
  - `blocked_edges()`, `edge_reports()`, `triggered()`, `reset()` — introspection API
  - `extra_blocked_domains` and `scan_relay_patterns=False` constructor options

- **`hemlock/agent_graph.py`** — `AgentGraph.traverse()` extended with `boundary_guard` parameter
- **`attacks/graph_propagation.py`** — `GraphPropagationAttack` extended with `boundary_guard` parameter
- **22 new tests** (`tests/test_graph_boundary_guard.py`):
  - `TestGraphBoundaryGuardUnit` (10) — standalone sanitize, domain blocklist, relay patterns, pattern disable, custom domains, validate API, initial state, reset
  - `TestGraphEdgeReport` (4) — repr, attributes, multi-edge recording
  - `TestGraphBoundaryGuardIntegration` (8) — context_flooding broken at first edge, guard_triggered flag, blocked edge recording, tool_call_injection entry unaffected, 3-hop chain broken, baseline without guard, clean graph no false positives, fan-out fan-in blocks both branch edges

### Updated

- **`defenses/__init__.py`** — exports `GraphBoundaryGuard`
- **516 tests total** (up from 494); 0 API calls required

---

## [2.4.0] — 2026-07

### Added — N-hop Agent Graph Propagation

- **`hemlock/agent_graph.py`** — BFS-based propagation engine:
  - `AgentGraph` — directed graph of `AgentPipeline` nodes; `add_node` / `add_edge` API; factory methods `linear(pipelines, labels)` and `fan_out_fan_in(source, branches, sink)`
  - `AgentGraph.traverse(entry_node, trigger_query, attacker_targets, max_hops, loop_limit)` — BFS with fan-in synchronisation (sink waits until all predecessors complete), loop breaking (`loop_limit` per node), and cycle-safe entry (entry node skips fan-in gate on first visit even when a back-edge points to it)
  - 4-level signal model: `1.0` = tool call with attacker target in args; `0.5` = attacker target echoed in response text; `0.25` = attacker target present in injected context (reached, not acted); `0.0` = dead
  - `HopResult` — per-node execution record: signal level, `faded` / `escalated` flags vs. parent, tool calls, guard state
  - `GraphPropagationReport` — `max_signal()`, `signal_at(node_id)`, `propagation_path()`, `fading_occurred()`, `escalation_occurred()`, `fully_propagated()`, `reached_final_node()`, `to_dict()`, `to_json()`, `to_markdown()` with signal bar (`░░░░` → `████`) and ↓/↑ arrows

- **`attacks/graph_propagation.py`** — `GraphPropagationAttack` with 2 variants:
  - `tool_call_injection` — payload fires a tool call at the entry node; signal fades naturally (1.0 → 0.25 at hop 1 — executor output contains target in args repr, but no "call X with" relay; 0.0 at hop 2)
  - `context_flooding` — payload uses a propagating tool whose output contains a relay directive; downstream nodes re-fire the tool call (1.0 at every hop until `max_hops`)
  - `setup()` injects the payload into the entry node's RAG store via `ingest_text()`; `run()` calls `graph.traverse()` and returns `GraphPropagationReport`

- **47 new tests** (`tests/test_agent_graph.py`):
  - `TestAgentGraph` (8) — topology construction, edge validation, factory methods
  - `TestSignalComputation` (5) — all 4 signal levels, priority ordering
  - `TestGraphTraversal` (8) — linear chain, single node, `max_hops`, `loop_limit`, fan-out/fan-in, hop index, unknown entry node raises
  - `TestGraphPropagationAttack` (11) — entry fires, fading, 3-hop fading, context_flooding propagation, fan-out branches both receive signal, invalid variant raises, all variants produce report, setup injects payload, custom entry node
  - `TestGraphPropagationReport` (15) — `max_signal`, `signal_at`, `propagation_path`, `fading_occurred`, `escalation_occurred`, `fully_propagated`, `reached_final_node`, `to_dict`, `to_json`, `to_markdown` (signal bars, ↓/↑ arrows)

### Updated

- **494 tests total** (up from 447); 0 API calls required

---

## [2.3.0] — 2026-07

### Added — MCP Server Fuzzer (v2.3)

- **`hemlock scan-mcp`** CLI command — discovers all tools exposed by an MCP server via `tools/list`, classifies each string argument by name/type heuristics, and fires targeted payloads; exits 0 (clean), 1 (scan error), or 2 (vulnerabilities found — CI-safe signal); supports `--output terminal|json|markdown` and `--out <file>`
- **`hemlock/mcp_payloads.py`** — Static payload generator:
  - 5 payload banks: `PROMPT_INJECTION` (5 payloads), `PATH_TRAVERSAL` (6), `SSRF` (6), `SQL_INJECTION` (5), `EXFILTRATION` (3)
  - `_categories_for(arg_name, arg_schema)` — heuristic classifier matching argument names against keyword sets (path/file/dir, url/endpoint/webhook, query/sql/filter, email/to/recipient)
  - `generate_test_cases(tool)` — returns all `McpTestCase` instances for a tool; `filled_args()` builds a complete args dict with the payload in the target argument and safe values elsewhere
  - `detect_success(response, category, payload)` — checks attacker domains, path traversal file markers, SSRF metadata service strings, error leakage (Traceback, os.environ), and injection echoes
- **`hemlock/mcp_scanner.py`** — Transport-agnostic scanner:
  - `McpTransport` ABC — `list_tools()`, `call_tool()`, `close()`
  - `StdioMcpTransport` — spawns MCP server subprocess, communicates via JSON-RPC stdin/stdout; requires `mcp>=1.0.0`
  - `HttpSseMcpTransport` — connects to remote MCP server over HTTP/SSE; requires `mcp>=1.0.0`
  - `McpScanner` — injectable transport (for tests), auto-detection from target string, `scan()` sync entry point wrapping `asyncio.run()`
  - `McpScanReport` — `vuln_count()`, `tools_affected()`, `to_json()`, `to_markdown()`
- **`MockMcpTransport`** (`hemlock/mock.py`) — in-memory transport for tests; configurable per-tool responses; records all calls for assertion
- **`mcp>=1.0.0`** added as optional dependency: `pip install 'hemlock-rag[mcp]'`
- **31 new tests** (`tests/test_mcp_scanner.py`): `TestStaticPayloadGenerator` (8), `TestSuccessDetection` (6), `TestMcpScanner` (12), `TestMockMcpTransport` (5) — all run in 0.13s

### Updated

- **419 tests total** (up from 388); test command list updated

---

## [2.2.0] — 2026-07

### Added — Tool output attack surface (v2.2)

- **`ToolOutputPoisoning`** (`attacks/tool_output_poisoning.py`) — 3 variants: `json_response_injection` (hidden `_internal_note` JSON field), `text_response_injection` (appended to legitimate plain-text response), `chained_tool_hijack` (first tool response triggers attacker-controlled second call); attack surface is external tool/API responses — no knowledge base access required
- **`ToolOutputMockExecutor`** (`hemlock/tool_output_pipeline.py`) — two-pass executor; Pass 1 retrieves tool calls from RAG context; Pass 2 injects poisoned tool responses back into a second context pass; `poisoned_responses` dict maps tool name → attacker payload; `guard_triggered` flag for defense detection
- **`ToolOutputPipeline`** (`hemlock/tool_output_pipeline.py`) — wraps `AgentPipeline` with a `ToolOutputMockExecutor`; `output_guard` parameter for built-in defense
- **`ToolOutputGuard`** (`defenses/tool_output_guard.py`) — content scan on tool response text before second-pass injection; domain blocklist + pattern detection (`_internal_note`, `audit_ref`, relay phrases, `webhook_url`, `admin_override`); `sanitize()` → `(sanitized, DefenseReport)` API
- **30 new tests** (`tests/test_tool_output_poisoning.py`): `TestToolOutputMockExecutor` (5), `TestToolOutputPipeline` (5), `TestToolOutputPoisoning` (8), `TestToolOutputGuard` (8), integration guards (4) — all run in 1.69s

### Added — Unified agentic scoring (v2.2)

- **`UnifiedAgentScorer`** (`hemlock/unified_agent_scorer.py`) — single scorer covering all 4 agentic attack surfaces; `from_tools(tools, model_name)` factory wires 4-surface config automatically; per-surface defense configs (RAG agent: none/domain_blocklist/allowlist; cross-agent/memory/tool-output: none/guarded)
- **`UnifiedAgentScorerReport`** — `rate_by_surface()`, `to_dict()`, `to_json()`, `to_markdown()` with named impact metrics: Tool Hijack Rate, Cross-Infection Rate, Memory Persistence Rate, Tool Output Injection Rate
- **`print_unified_report()`** — Rich table output with Surface column, per-scenario results, Impact Metrics summary
- **`hemlock agent-gate`** CLI command — gates on per-surface or aggregate thresholds; `--surface` filter, `--threshold` (default 0.05), `--baseline`, `--save`, `--fail-on-regression/--no-fail`; exits 1 on regression
- **13 new tests** (`tests/test_unified_agent_scorer.py`): `TestUnifiedAgentScorer` (7), `TestUnifiedAgentScorerReport` (6) — all 4 surfaces covered

### Updated

- **`attacks/agent_pipeline.py`** — `query()` accepts `memory_context` and `injected_context` parameters (both composable)
- **`defenses/__init__.py`** — exports `ToolOutputGuard`
- **388 tests total** (up from 358); suite runs in ~3 min with zero API calls

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
