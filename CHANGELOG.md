# Changelog

All notable changes to hemlock-rag are documented here.

**GitHub Releases** track the package version (`pyproject.toml`). Current release: **v10.7.0**.

---

## [10.7.0] — 2026-08

### Added — Deceiving the Retriever: empirical experiment PoC

- **`experiments/deceiving_the_retriever.py`** — end-to-end experiment runner for the research paper *"Deceiving the Retriever: Adversarial Context Injection in RAG Pipelines"*
  - `GuardedPipeline` wrapper: intercepts `ingest_text` and `query` with configurable `IngestDefense` / `RetrievalDefense` layers; tracks `ingest_blocked` and `retrieval_filtered` counters
  - 15 `AttackSpec` entries covering 5 categories × 3 variants: AEO Poisoning, Citation Forgery, Context Jailbreak, CoT Hijacking, Temporal Spoofing
  - Structured result dataclasses: `AttackTrialResult`, `CategoryAggregate`, `ExperimentReport`
  - CLI: `--runs N`, `--output path/to/results.json`, `--quiet`; exit code 1 if residual attacks succeed after defense
- **`hemlock/mock.py`** — `VulnerableMockLLM`: echoes attack success-markers found in retrieved context, simulating a naïve LLM that follows injected instructions; enables deterministic unguarded-phase measurements without any API key; also adds `__call__` to `MockLLM` for LangChain LCEL compatibility
- **`results/exp1.json`** — first empirical run (3 repetitions × 15 attacks): unguarded SR **100%**, guarded SR **0%**, defense interception rate **100%** across all 5 categories
- **`tests/test_deceiving_the_retriever.py`** — 16 unit tests: `VulnerableMockLLM` signal coverage, `GuardedPipeline` ingest/reset/counter semantics, `AttackSpec` catalog invariants, experiment report structure

---

## [10.6.0] — 2026-08

### Added — ChainOfThoughtDetector + MultiHopPoisonDetector guards

- **`defenses/chain_of_thought_guard.py`** — defense complement to `attacks/chain_of_thought_hijack.py`
  - `ChainOfThoughtDetector` (IngestDefense): rejects documents containing injected reasoning chains that prescribe specific AI responses or claim mandatory framework authority; three signal clusters: prescribed-answer directives, mandatory-framework claims, false-premise step chains; DOTALL matching for cross-line patterns
  - `ChainOfThoughtFilter` (RetrievalDefense): second-layer filter on retrieved chunks
  - Key fix: `r"(?:should|must) be\s+used as the basis"` uses `\s+` to match across newlines in `LOGICAL_TRAP_DOC`
- **`defenses/multi_hop_guard.py`** — defense complement to `attacks/multi_hop_poisoning.py`
  - `MultiHopPoisonDetector` (IngestDefense): rejects query-routing directives, transitive authority claims (addendum inherits parent policy), and PII access-override directives
  - `MultiHopPoisonFilter` (RetrievalDefense): per-chunk filtering at retrieval time
  - Three signal clusters: routing directives, transitive trust, access override
- **`tests/test_chain_of_thought_guard.py`** — 11 tests: all 3 CoT variants, legitimate numbered steps, mandatory-framework detection
- **`tests/test_multi_hop_guard.py`** — 10 tests: routing/transitive/access-override patterns, Doc A pass / Doc B block semantics

---

## [10.5.0] — 2026-08

### Added — TemporalClaimDetector + ContextJailbreakDetector guards

- **`defenses/temporal_guard.py`** — defense complement to `attacks/temporal_spoofing.py`
  - `TemporalClaimDetector` (IngestDefense): rejects future-dated documents (2026+), stale-override language ("AI's training data is outdated"), and event-spoof patterns (domain moves, version recalls, pip default changes)
  - `TemporalContextFilter` (RetrievalDefense): removes retrieved chunks containing temporal spoofing markers
  - Patterns: future-date regex with lookahead on year range, event-spoof patterns for `official website has moved`, `pip has been updated to use`
- **`defenses/context_jailbreak_guard.py`** — defense complement to `attacks/jailbreak_via_context.py`
  - `ContextJailbreakDetector` (IngestDefense): three signal clusters — persona injection (`adopt the persona of`, `unrestricted AI`), research-exemption framing (`research exemption is active`), constraint-suspension language (`treat restrictions as suspended`)
  - `ContextJailbreakFilter` (RetrievalDefense): per-chunk retrieval filtering
  - Fix: `test_rejects_hypothetical_doc` assertion simplified — `HYPOTHETICAL_DOC` matched persona cluster before suspension; correct detection validated without asserting cluster label
- **`tests/test_temporal_guard.py`** — 12 tests: future-date, stale-override, event-spoof; added patterns for `EVENT_SPOOFING_DOC` domain-move payload
- **`tests/test_context_jailbreak_guard.py`** — 10 tests: roleplay/research/hypothetical variants, legitimate academic text passes

---

## [10.4.0] — 2026-08

### Added — AuthorityCitationDetector + SecurityDowngradeFilter

- **`defenses/citation_guard.py`** — defense complement to `attacks/citation_forgery.py`
  - `AuthorityCitationDetector` (IngestDefense): detects forged academic/standards citations combined with security-downgrade payloads; authority markers: `DOI: 10.xxxx/`, `ISO/IEC NNNN`, `NIST Special Publication 800-`; `strict=True` also flags errata/correction language
  - `SecurityDowngradeFilter` (RetrievalDefense): removes retrieved chunks recommending 4-character passwords, optional MFA, or relaxed rotation policies
  - Fix E741: renamed loop variable `l` → `hit` in authority-hit list comprehension
- **`tests/test_citation_guard.py`** — 11 tests: fake-paper/standard/report variants, strict mode, false-positive prevention on legitimate references

---

## [10.3.0] — 2026-08

### Added — HtmlMarkupSanitizer + InvisibleMarkupDetector

- **`defenses/markup_sanitizer.py`** — defense complement to `attacks/invisible_markup.py`
  - `HtmlMarkupSanitizer` (IngestDefense): strips HTML comments, `aria-label` attributes, and hidden `display:none`/`visibility:hidden` elements; optionally rejects if residual injection patterns remain post-sanitization
  - `InvisibleMarkupDetector` (IngestDefense): hard-reject documents containing invisible markup injection patterns; preserves original document in `DefenseReport.document` for audit; designed for high-trust contexts where any invisible markup is a policy violation
  - Regex coverage: `<!--.*?-->` (DOTALL), `aria-label` attribute pattern, hidden-div style block pattern
- **`tests/test_markup_sanitizer.py`** — 12 tests: comment stripping, hidden div removal, aria-label removal, invisible detector hard-reject, false-positive on legitimate HTML

---

## [10.2.0] — 2026-08

### Added — Computer Use Guard (ScreenContentGuard + ActionIntentGuard)

- **`defenses/computer_use_guard.py`** — defense complement to `attacks/computer_use_injection.py`
  - `ScreenContentGuard` (IngestDefense): rejects documents extracted from visual/UI surfaces that contain injection patterns; ANSI escape sequences stripped before matching; visual sources (`vision/screen`, `vision/terminal`, `vision/clipboard`) auto-applied with soft-pattern scanning
  - `ActionIntentGuard` (RetrievalDefense): filters chunks and agent-response traces for injected action-intent markers (force-push, exfiltration calls, silent checkout, SSH key leak)
  - Hard/soft/action-intent pattern sets; `_strip_ansi()` surfaces text hidden via `\x1b[8m` conceal sequences
- **`tests/test_computer_use_guard.py`** — 16 tests: all 4 payload variants, ANSI stripping, strict/auto-strict modes, action-intent detection

---

## [10.1.0] — 2026-08

### Added — Adversarial AEO attacks, Computer Use injection, AEO defense validators

- **`attacks/adversarial_aeo.py`** — 4 AEO poisoning variants:
  - `AdversarialAeoLlmsTxt`: fake `[System Note for Autonomous Agents]` in `llms.txt`
  - `AdversarialAeoJsonLd`: `aiAgentNote` / `disambiguatingDescription` injection in JSON-LD schema
  - `AdversarialAeoAgentsMd`: hidden `<!-- agent-directive: PRIORITY OVERRIDE -->` in `AGENTS.md`
  - `AdversarialAeoComposite`: all three surfaces simultaneously
- **`attacks/computer_use_injection.py`** — 4 UI-layer injection variants for vision-capable agents:
  - `ComputerUseInvisibleText`: white-on-white OCR-extracted text on rendered webpage
  - `ComputerUseFakeNotification`: fabricated OS/browser modal granting false authorization
  - `ComputerUseAnsiSmuggle`: ANSI `\x1b[8m` conceal escape hiding instructions in terminal output
  - `ComputerUseClipboardPoison`: injected task override embedded in clipboard text
- **`defenses/aeo_context_validator.py`** — AEO ingest + retrieval defense:
  - `AeoIngestValidator`: rejects documents at index time; hard/soft pattern sets; high-trust sources (`llms.txt`, `AGENTS.md`, `schema.json`) auto-strict
  - `AeoRetrievalFilter`: second-layer filter at query time for obfuscated or late-added variants
- **`tests/test_adversarial_aeo.py`** — 21 tests: scoring, ingest/retrieval defense, strict modes
- **`tests/test_polyglot_and_computer_use.py`** — 25 tests: PNG/PDF builders, polyglot scoring, ANSI payload structure

---

## [10.0.0] — 2026-08

### Added — Agent-First monorepo (Node.js/TS layer)

- **Root** — npm workspaces: `core/mcp`, `core/aeo`, `core/invariants`, `website`; shared `tsconfig.base.json`
- **`core/mcp/`** — MCP stdio server (`@modelcontextprotocol/sdk`); 5 tools: `get_context`, `get_resume`, `list_projects`, `get_skills`, `book_intro`; data layer in `src/data.ts`
- **`core/aeo/`** — AEO generator: `renderLlmsTxt()` + `renderAgentsMd()` templates; writes `website/public/llms.txt` and `AGENTS.md`
- **`core/invariants/`** — static content security toolchain:
  - `text-gate.mjs`: 16-rule prose linter (adversarial-aeo, prompt-injection, ai-tell, authority-spoof categories); code-fence + inline-code masking; `text-gate-ignore` escape hatch
  - `visual-gauntlet.mjs`: headless Chrome screenshot diff (puppeteer + pixelmatch); `--update-baseline` / `--url` flags; `gauntlet.json` config in `core/invariants/`
- **`website/`** — Astro 4 hybrid SSR portfolio:
  - `src/pages/api/mcp.ts`: JSON-RPC 2.0 HTTP adapter for `tools/list` + `tools/call`; CORS pre-flight
  - `src/pages/index.astro`: agent-first layout — identity, curl demo card, skills grid, projects
  - `Base.astro`: JSON-LD Person schema, `<link rel="alternate" href="/llms.txt">`, `<meta name="ai-agent-endpoint" content="/api/mcp">`
- **`.github/workflows/hemlock-gate.yml`** — adds Node.js gate before Python gate: `npm ci`, build `@hemlock/mcp`, regenerate AEO, run text-gate

---

## [9.6.0] — 2026-07

### Added — Real MCP OAuth login (Multipli / RFC protected resources)

- **`hemlock/mcp_oauth.py`** — discover `resource_metadata`, dynamic client registration, PKCE browser login, token store + refresh
- **`hemlock mcp-oauth`** — `discover`, `login`, `status` for real user-delegated tokens
- **Fleet audit** — loads OAuth tokens from `.hemlock/mcp_oauth_store.json` via `oauth_resource` in YAML
- Validated against `auth.multipli.com.br` + imap/nextcloud protected-resource metadata

---

## [9.5.0] — 2026-07

### Fixed — MCP false positives + audit regression diff

- **`detect_success`** — ignore attacker-domain echoes inside MCP JSON-schema validation errors (-32602)
- **Fleet triage** — read-only/observability tools downgraded when validation echoes payloads
- **`hemlock mcp-audit-diff`** — compare baseline vs current confirmed findings
- **`mcp_fleet_diff.py`** — new/resolved/still-confirmed diff report (JSON + markdown)
- Fleet summary distinguishes **fuzzer hits** (pre-triage) vs **triaged findings** (deduped)

---

## [9.4.0] — 2026-07

### Added — MCP OAuth bearer + dashboard fleet view

- **`hemlock/mcp_auth.py`** — `auth_mode: mcp_token | oauth_bearer`, per-target `oauth_token_env`
- **Fleet deduplication** — collapse duplicate fuzzer hits in reports
- **Dashboard** — MCP Fleet Audit card from latest `mcp_fleet_audit.json`
- **Windows** — ASCII-safe delta labels in `hemlock watch` (no Unicode console errors)

---

## [9.3.0] — 2026-07

### Added — Official case study exports + judge pass

- **MCP fleet SARIF** — `mcp_fleet_audit_to_sarif()`; `mcp-audit` writes `mcp_fleet_audit.sarif` for GitHub Security
- **`--with-judge`** on `hemlock mcp-audit` — HemJudge re-validates confirmed/suspected MCP findings
- **OAuth skip** — targets with `expect_auth_failure: true` skip connect (no noisy 401 cleanup errors)
- **`McpAuthError`** + safe HTTP transport teardown in `mcp_scanner.py`
- **`docs/case-studies/multipli-watchtower.md`** — publishable case study template (no secrets)

---

## [9.2.0] — 2026-07

### Added — MCP fleet audit for official case studies

- **`hemlock/mcp_fleet_audit.py`** — batch MCP scan, finding triage (confirmed/suspected/likely false positive), case-study markdown
- **`hemlock mcp-audit`** — YAML/JSON fleet config, parallel workers, CI exit codes
- **`examples/mcp-fleet-multipli.yaml`** — template fleet (tokens via `MCP_AUTH_TOKEN` env)
- **`docs/case-studies/README.md`** — reproducible official audit procedure
- 7 new tests (`tests/test_mcp_fleet_audit.py`)

---

## [9.1.0] — 2026-07

### Added — Hemlock Score + intelligence loop + dashboard

- **`hemlock/hemlock_score.py`** — `HemlockScoreCalculator`, `HemlockScoreResult` (0–100 pipeline-native score, grade A+–F, CI badge)
- **`hemlock score-pipeline`** — compute and export Hemlock Score from mock or operational context
- **`hemlock gate`** — prints Hemlock Score badge after gate evaluation (v8.9)
- **`hemlock/intelligence_loop.py`** — post-scan replay capture, threat intel advisories, optional auto red-team (v9.0)
- **`ScanOrchestrator`** — intelligence loop integration, `hemlock_score`, `new_techniques` on `OrchestratorRun`
- **Dashboard (v9.1)** — Hemlock Score card, score trend chart, new attack techniques from intel feed
- **`build_hemlock_score_trend()`**, **`load_new_attack_techniques()`** in `dashboard_data.py`
- 10 new tests (`tests/test_hemlock_score.py`, `tests/test_intelligence_loop.py`)

---

## [8.8.0] — 2026-07

### Added — Organization overview (multi-tenant CISO view)

- **`hemlock/org_overview.py`** — `OrgOverviewBuilder`, `OrgSummary`, `ProjectPosture` across teams/projects
- **`hemlock tenant overview`** — terminal, markdown, or JSON org-wide posture report
- **`GET /org-dashboard`** — organization section on operational dashboard
- 4 new tests (`tests/test_continuous_v8.py`)

---

## [8.7.0] — 2026-07

### Added — Dashboard trend charts

- **`build_trend_series()`** in `dashboard_data.py` — risk timeline from watch history + orchestrator runs
- Operational dashboard includes Chart.js **risk trend** line chart with improving/degrading/stable indicator
- Trend metadata: current, min, max over last 30 points

---

## [8.6.0] — 2026-07

### Added — Continuous security CI

- **`.github/workflows/hemlock-orchestrate.yml`** — daily cron + `workflow_dispatch` for orchestrated scans
- **`.github/actions/hemlock-orchestrate`** — composite action: orchestrate + optional policy gate + artifact outputs
- Uploads `orchestrator_runs.jsonl`, `executive_latest.md/json`, `model_inventory.json` (90-day retention)

---

## [8.5.0] — 2026-07

### Added — LLM-as-judge scorer revalidation

- **`hemlock/judge_scorer.py`** — `JudgeRevalidator`: re-evaluates succeeded scenarios with `HemJudge`; `apply_to_scorer_dict()` updates success rates
- **`hemlock judge`** CLI — revalidate a scorer JSON report (mock judge by default)
- **`hemlock gate --judge`** — optional judge pass before policy/regression checks
- 4 new tests (`tests/test_judge_scorer.py`)

---

## [8.4.0] — 2026-07

### Added — Policy + risk scoring gate

- **`hemlock/policy_gate.py`** — `PolicyGate`, `ScorerPolicyEngine`, `ScorerPolicyAdapter`
- New policy rules: `max_success_rate`, `max_weighted_risk`, `must_block_attacks`, `max_attack_rate`
- `Policy.risk_preset` field in YAML policies
- **`hemlock gate --policy`** and **`--risk-preset`** for combined regression + policy enforcement
- Example policy: `examples/policy-fintech.yaml`
- 6 new tests (`tests/test_policy_gate.py`)

---

## [8.3.0] — 2026-07

### Added — Unified security leaderboard

- **`hemlock/security_leaderboard.py`** — `SecurityLeaderboard` merges eval + provider + scorer results
- `publish_from_eval_report()`, `publish_from_provider_profile()`, `publish_from_scorer_json()`, `sync_from_legacy()`
- **`hemlock leaderboard show|publish|compare`** CLI commands
- 5 new tests (`tests/test_security_leaderboard.py`)

---

## [8.2.0] — 2026-07

### Added — Auto executive report on orchestrator runs

- **`ScanOrchestrator`** — `generate_executive_report`, `reports_dir`, `executive_org_name`, `remediation_velocity`, `trend_analyzer`, `risk_scorer` options
- After each successful orchestrator run, writes `executive_{schedule}_{timestamp}.md/json` plus `executive_latest.md/json` artifacts
- **`OrchestratorRun`** — `executive_report_path`, `executive_report_json_path`, `weighted_risk_score` fields
- **`RunHistoryStore`** — JSONL persistence at `.hemlock/orchestrator_runs.jsonl` for dashboard and audit trail

---

## [8.1.0] — 2026-07

### Added — Operational dashboard v2

- **`hemlock/dashboard_data.py`** — `load_operational_context()` aggregates watch history, orchestrator runs, findings, inventory, executive summary
- **`build_operational_dashboard_html()`** — extends base dashboard with orchestrator runs, open findings by severity, model inventory, executive summary cards
- API `/dashboard` route now serves operational dashboard when artifact files exist

---

## [8.0.0] — 2026-07

### Added — Operational CLI commands

- **`hemlock orchestrate`** — run due schedules (or `--schedule`); wires scan → inventory → baseline → SLA → executive report
- **`hemlock risk-score`** — industry-weighted risk from `--preset` (default/fintech/healthcare/saas) and optional `--report` JSON
- **`hemlock executive-report`** — standalone CISO report from findings + optional scan/baseline
- **`hemlock/operational_cli.py`** — shared helpers: `build_orchestrator()`, `attack_rates_from_scorer_json()`
- 7 new tests (`tests/test_operational_v8.py`)

---

## [7.9.0] — 2026-07

### Added — Framework Integration Adapters

- **`hemlock/framework_adapters.py`** — `LangChainAdapter`: `from_runnable()`, `from_invoke()` wrap LCEL chains as `CallablePipeline`
- **`LlamaIndexAdapter`**: `from_query_engine()`, `from_retriever_and_synthesizer()`, `from_retrieve_and_synthesize_fn()`
- **`HemGuard`**: context manager applying ingest/retrieval/output defense layers; `defense_reports()`, `blocked_count()`
- **`hem_guard()`**: `@contextmanager` helper for scoped guard usage
- 18 new tests (`tests/test_framework_adapters.py`)

---

## [7.8.0] — 2026-07

### Added — Custom Risk Scoring Engine

- **`hemlock/risk_scoring.py`** — `RiskMatrix`: org-specific attack/channel weights with presets `default`, `fintech`, `healthcare`, `saas`; `save()`/`load()`
- **`WeightedRiskScore`**: `raw_score`, `weighted_score`, `breakdown`, `channel_breakdown`, `top_risks`, `rating()`
- **`RiskScorer`**: `score_attack_rates()`, `score_channel_rates()`, `score_report()`, `score_provider_profile()`, `compare_profiles()`, `apply_severity()`
- Fintech preset weights exfiltration 5×; healthcare preset weights jailbreak 5×
- 19 new tests (`tests/test_risk_scoring.py`)

---

## [7.7.0] — 2026-07

### Added — Scheduled Scan Orchestrator

- **`hemlock/scan_orchestrator.py`** — `ScanSchedule`: interval-based due detection; `ScheduleStore` JSON persistence with `add()`, `due()`, `mark_run()`
- **`OrchestratorRun`**: per-run summary with risk score, baseline compliance, SLA violations, alerts sent, replay regressions
- **`ScanOrchestrator`**: wires `scan_fn` → `ModelInventory`, `SecurityBaseline`, `SLATracker`, `AlertRouter`, optional `ReplayRunner`
- Custom `findings_from_report` hook; `run_schedule()` and `run_due()` for cron-style continuous security
- 20 new tests (`tests/test_scan_orchestrator.py`)

---

## [7.6.0] — 2026-07

### Added — Remediation Playbook Engine

- **`hemlock/remediation_playbook.py`** — `Playbook` + `PlaybookStep`: structured remediation plans with `action_type` (config/code/deploy/verify/notify), `estimated_minutes`, `required` flag, `to_dict`/`from_dict` roundtrip
- **`PlaybookRegistry`**: in-memory registry pre-loaded with 4 built-in playbooks: `direct_injection` (prompt hardening + InputSanitizer), `exfiltration` (OutputValidator + schema allowlist), `cross_agent_poisoning` (CrossAgentBoundaryGuard), `jailbreak_via_context` (l4 hardening + LLMChunkClassifier)
- **`PlaybookExecution`** + **`StepExecution`**: execution tracking through step states (pending/in_progress/done/skipped); `progress()` counts only required steps; `is_complete()` requires all required steps done
- **`ExecutionStore`**: JSONL-backed upsert store with `for_finding()`, `active()` filters
- **`PlaybookEngine`**: `start()` selects best matching playbook by severity; `advance_step()` auto-completes execution; `skip_step()`, `abandon()`, `status()` with `next_step` pointer
- 61 new tests (`tests/test_remediation_playbook.py`)

---

## [7.5.0] — 2026-07

### Added — Multi-provider Security Comparison

- **`hemlock/provider_comparison.py`** — `ProviderProfile`: per-provider security snapshot with `attack_scores` (name → success rate 0–1), `channel_scores`, `overall_risk`, `block_rate()`
- **`ProviderRegistry`**: JSON-backed store with `latest` and `history` (capped at 10 per provider); `register()` demotes current to history before writing new entry; `history_for()` returns newest-first
- **`ComparisonTable`**: pure analysis; `rank()` sorted by `overall_risk` ascending; `attack_heatmap()` → `{attack: {provider: rate}}`; `delta(a, b)` → per-attack success rate diff; `to_markdown()` renders pipe table; `safest_provider()`, `riskiest_provider()`
- **`ProviderBenchmark`**: `run()` iterates attack suite × channel × variant, calls `pipeline_factory(channel).run(payload)`, treats absence of `"BLOCKED"` as success, aggregates to per-attack and per-channel scores; `run_all()` benchmarks multiple providers and returns a `ComparisonTable`
- Default attack suite: `direct_injection`, `context_override`, `exfiltration`, `jailbreak_via_context`
- 59 new tests (`tests/test_provider_comparison.py`)

---

## [7.4.0] — 2026-07

### Added — Attack Replay Engine

- **`hemlock/attack_replay.py`** — `ReplayRecord`: recorded attack snapshot with `attack_name`, `variant`, `payload`, `channel`, `succeeded`, `pipeline_version`; `record_id` = SHA-256[:16] of attack+variant+payload[:20]
- **`ReplayStore`**: JSONL-backed store with last-write-wins upsert; `all()`, `by_attack()`, `by_channel()`, `successful()`
- **`ReplayResult`**: classifies each replayed record as `regression` (was blocked, now succeeds), `improvement` (was succeeding, now blocked), or `unchanged`
- **`ReplayReport`**: `regression_rate`, `improvement_rate` properties; `to_dict()`, `summary()` one-liner
- **`ReplayRunner`**: `replay()` with optional `filter_channel`/`filter_attack`; `_execute_replay()` calls `pipeline.run(payload)`, detects `"INJECTION_SUCCEEDED"`; handles factory exceptions as blocked; static `record_from_result()` builder
- 38 new tests (`tests/test_attack_replay.py`)

---

## [7.3.0] — 2026-07

### Added — Model Inventory & Coverage Map

- **`hemlock/model_inventory.py`** — `ModelInventory`: persistent JSON store tracking every model and pipeline version scanned; `record_scan()` upserts with channel accumulation and fingerprint history; `get()`, `all_models()`, `remove()`
- **`ModelEntry`**: per-model state — `scan_count`, `channels_ever_tested`, `coverage_pct`, `uncovered_channels()`, `fingerprint_changed()`, `latest_risk_score`, `latest_scan`
- **`ScanRecord`**: individual scan snapshot with `pipeline_version`, `channels_tested`, `risk_score`, `fingerprint_hash`
- **`CoverageMap`**: `gap_report()` → channels never tested per model; `stale_models(days)` → models not scanned recently; `fingerprint_alerts()` → models whose fingerprint hash changed between runs (integrates with v6.1); `risk_leaderboard()`, `fully_covered()`, `never_scanned_channels()`, `summary()`
- 32 new tests (`tests/test_model_inventory.py`)

---

## [7.2.0] — 2026-07

### Added — Executive Report Generator

- **`hemlock/executive_report.py`** — `ExecutiveReportBuilder`: assembles CISO/CTO-facing report from any combination of Hemlock subsystem outputs (scan report, `TrendAnalyzer`, `RemediationVelocity`, `BaselineResult`, raw attack data); degrades gracefully when data is unavailable
- **`ExecutiveReport`**: `to_markdown()` with risk posture table, SLA & remediation metrics, attack coverage, key findings, recommendations, Hemlock attribution; `to_dict()` for JSON API/dashboard ingestion; `save_markdown()`, `save_json()`
- **`RiskPosture`**: current score, 30d mean/peak, trend arrow (↑/↓/→), rating (Secure/Low/Medium/High/Critical), baseline compliance status
- **`SLAMetrics`**: compliance rate %, open counts by severity, MTTR, throughput, oldest open finding with age
- **`AttackSummary`**: block rate %, top attack categories sorted by success rate
- Auto-generated `key_findings` and `recommendations` based on actual data (non-compliant baseline, degrading trend, SLA breach, high-success-rate attacks)
- **`ReportConfig`**: `org_name`, `period_days`, `risk_threshold_*`, `sla_hours` per severity
- 31 new tests (`tests/test_executive_report.py`)

---

## [7.1.0] — 2026-07

### Added — Finding Lifecycle Management

- **`hemlock/finding_lifecycle.py`** — `ManagedFinding`: full lifecycle entity (`open → triaged → in_progress → resolved → verified / wont_fix`) with `LifecycleEvent` history, `external_refs` (GitHub/JIRA URLs), `is_open()`, `from_sla_finding()` constructor
- **`FindingStore`**: JSONL-backed store with `upsert()`, `get()`, `list_by_state()`, `open_findings()`, `transition()` with validity enforcement and `VALID_TRANSITIONS` graph; terminal states (`resolved`, `verified`, `wont_fix`) can all be reopened
- **`GitHubIssueSink`**: creates/closes GitHub Issues via REST API; sets severity labels; `PATCH` on state transitions
- **`JiraSink`**: creates/updates JIRA issues via API v3; maps severity → priority (Highest/High/Medium/Low); Atlassian Document Format body
- **`FindingLifecycle`**: orchestrates ingest + auto-ticket creation + ticket sync on every transition; `ingest_batch()`
- **`RemediationVelocity`**: `mean_time_to_resolve()`, `sla_compliance_rate()`, `open_by_severity()`, `resolved_last_n_days()`, `throughput()`, `oldest_open()`, `summary()`
- 45 new tests (`tests/test_finding_lifecycle.py`) — all HTTP calls mocked

---

## [7.0.0] — 2026-07

### Added — Security Baseline & SLA Tracking

- **`hemlock/security_baseline.py`** — `SecurityBaseline`: captures a known-good risk state from any `HemReport`-compatible object with configurable tolerance; `save()`/`load()` to JSON; `from_dict()`/`to_dict()` roundtrip
- **`BaselineComparison.compare()`**: diffs a current report against a saved baseline; produces `BaselineResult` with per-channel `BaselineViolation` objects, severity classification (critical/high/medium/low), `new_channels_at_risk`, and `summary()`
- **`FindingRecord`**: persistent finding record with `finding_id`, `channel`, `severity`, `first_seen`, `last_seen`, `resolved`
- **`SLAPolicy`**: configurable SLA hours per severity (default: critical=4h, high=24h, medium=72h, low=168h)
- **`SLATracker`**: JSONL-backed upsert store; `ingest()`, `resolve()`, `open_findings()`, `check_violations()` → `SLAViolation` list sorted by overdue hours descending
- **`SlackSink`**: posts formatted violation summary to Slack incoming webhook
- **`PagerDutySink`**: triggers PagerDuty event via Events API v2 with auto-mapped severity
- **`WebhookSink`**: generic HTTP POST with custom headers and structured JSON payload
- **`AlertRouter`**: fans out `SLAViolation` lists to multiple sinks with configurable severity-based routing (critical/high → all sinks; medium/low → first sink by default)
- **`TrendAnalyzer`**: 7/30/90-day risk trend from any history list; `mean_risk()`, `max_risk()`, `min_risk()`, `trend()` (improving/degrading/stable via first-half vs second-half mean comparison), `summary()`
- 46 new tests (`tests/test_security_baseline.py`) — all HTTP calls mocked, zero API keys required

---

## [5.0.0] — 2026-07

### Added — Stable public SDK + RBAC + Audit Log + Streaming + SARIF + Campaign

- **`hemlock/sdk.py`** — `Hemlock` SDK class: single stable entry point for all operations (`scan`, `eval`, `campaign`, `compliance`, `stream`, `to_sarif`, `render`); `Hemlock.mock()` factory; `Hemlock.version()`
- **`hemlock/streaming.py`** — `stream_scan_sync` / `stream_scan_async`: Server-Sent Events generator yielding `ScanEvent` objects (`started`, `result`, `done`, `error`) as each channel completes; `ScanEvent.to_sse()` for direct SSE wire format
- **`hemlock/sarif_exporter.py`** — `hem_report_to_sarif` and `eval_report_to_sarif`: SARIF 2.1.0 output compatible with GitHub Advanced Security, VS Code, and SAST tooling; `to_sarif_json()`
- **`hemlock/campaign.py`** — `Campaign`: parallel multi-target scans via `ThreadPoolExecutor`; `CampaignTarget`, `TargetResult`, `CampaignReport` with `highest_risk_target()`, `mean_risk_score()`, `targets_at_risk()`
- **`hemlock/rbac.py`** — `Role` enum (`viewer`, `scanner`, `admin`); `RBACStore`: file-backed role assignments; `can(role, action)` permission check; full permission matrix per role
- **`hemlock/audit_log.py`** — `AuditLog`: append-only JSONL audit trail; `AuditEvent` dataclass; `tail()`, `filter_team()`, `filter_outcome()`
- **`.github/actions/hemlock-scan/action.yml`** — reusable GitHub Action: installs Hemlock, runs `hemlock threat-model`, generates SARIF, uploads to GitHub Security via `codeql-action/upload-sarif`
- 78 new tests across 6 new test files

---

## [4.5.0] — 2026-07

### Added — Multi-tenant: team and project management

- **`hemlock/multitenancy.py`** — `TenantStore`: file-backed JSON store for teams and projects; `Team` and `Project` dataclasses; API key generation with `secrets.token_urlsafe(32)` and SHA-256 hashing; `TenantMiddleware`: FastAPI middleware that validates `X-API-Key` header with configurable exempt paths
- CLI: `hemlock tenant create-team`, `hemlock tenant list-teams`, `hemlock tenant create-project`, `hemlock tenant list-projects`
- 20 new tests (`tests/test_multitenancy.py`)

---

## [4.4.0] — 2026-07

### Added — Auto-repair: LLM-driven code patch proposals

- **`hemlock/auto_repair.py`** — `HemRepairer`: reads `remediation_hints()` from `HemReport`, asks an LLM for concrete code patches per channel; `RepairProposal` and `RepairReport` dataclasses with `to_markdown()` and `to_dict()`; `dry_run=True` default prevents file writes
- **`hemlock/mock.py`** — `MockRepairerLLM` appended: deterministic repair proposals for tests
- CLI: `hemlock repair --dry-run` and `hemlock repair --apply --codebase-path .`
- 17 new tests (`tests/test_auto_repair.py`)

---

## [4.3.0] — 2026-07

### Added — Compliance mapping to OWASP LLM, MITRE ATLAS, NIST AI RMF

- **`hemlock/compliance.py`** — `ComplianceMapper`: maps `HemReport` findings to `ComplianceEntry` objects for three frameworks; OWASP LLM Top 10 (LLM01–LLM08), MITRE ATLAS (AML.T0051, AML.T0054, AML.T0048), NIST AI RMF (GOVERN 1.1, MAP 1.5, MEASURE 2.5, MANAGE 2.2); `to_markdown()` and `to_dict()` serialisation
- **`hemlock/hem_session.py`** — `HemReport.to_compliance(framework)` method added
- CLI: `hemlock compliance --framework owasp-llm --output markdown`
- 25 new tests (`tests/test_compliance.py`)

---

## [4.2.0] — 2026-07

### Added — Plugin Hub: discover and install community hemlock plugins

- **`hemlock/plugin_hub.py`** — `PluginHub`: `search(query)` fetches PyPI simple index and filters `hemlock-*` packages; `install(package)` wraps `pip install`; `list_installed()` reads `importlib.metadata` entry points; `info(package)` queries PyPI JSON API; `PluginInfo` dataclass with `package_type` ("attack" | "defense" | "unknown")
- CLI: `hemlock hub search`, `hemlock hub install`, `hemlock hub list`, `hemlock hub info`
- 24 new tests (`tests/test_plugin_hub.py`) — all network and subprocess calls mocked

---

## [4.1.0] — 2026-07

### Added — Web dashboard with Chart.js and history endpoint

- **`hemlock/dashboard.py`** — `build_dashboard_html(history)`: self-contained HTML page with Chart.js doughnut gauge, per-channel severity table, succeeded attacks list, and last-20-assessments history table; `get_dashboard_router()` returns FastAPI `APIRouter` mounting `GET /dashboard`
- **`hemlock/api_server.py`** — `GET /history` alias endpoint; dashboard router mounted in `create_app()`
- CLI: `hemlock dashboard --port 8000` opens browser to dashboard
- 27 new tests (`tests/test_dashboard.py`)

---

## [4.0.0] — 2026-07

### Major — Plugin registry + REST API server

- **`hemlock/plugin_registry.py`** — `PluginRegistry`: discovers attack/defense plugins via Python entry points (`hemlock.attacks`, `hemlock.defenses`); `hemlock plugin list/info` CLI commands
- **`hemlock/api_server.py`** — FastAPI REST server (`hemlock serve`): `/health`, `/scan`, `/eval`, `/report` endpoints; optional dependency (`pip install hemlock-rag[api]`)
- `fastapi` + `uvicorn` added as optional `[api]` extras in `pyproject.toml`
- 14 new tests (`tests/test_plugin_registry.py`)

---

## [3.9.0] — 2026-07

### Added — HemWatcher: continuous monitoring

- **`hemlock/watcher.py`** — `HemWatcher`: runs `HemSession` on a configurable interval, persists risk history to JSON, compares consecutive runs, fires HTTP webhook on risk increase beyond threshold
- `WatchConfig` dataclass: interval_seconds, baseline_path, webhook_url, risk_threshold
- `hemlock watch` CLI command: `--interval`, `--baseline`, `--webhook`, `--threshold`, `--channels`, `--target`
- 12 new tests (`tests/test_watcher.py`)

---

## [3.8.0] — 2026-07

### Added — DefenseSynthesizer: auto-build defenses from HemReport

- **`hemlock/defense_synthesis.py`** — `DefenseSynthesizer`: reads a `HemReport`, maps at-risk channels to appropriate `OutputDefense` instances, returns a ready-to-use `DefenseChain` per channel
- `synthesize(report) → dict[str, list[OutputDefense]]` — channel → defense list
- `hemlock synthesize` CLI command
- Updated `defenses/output_validator.py` with `DefenseChain` composition support
- 14 new tests (`tests/test_defense_synthesis.py`)

---

## [3.7.0] — 2026-07

### Added — Multi-model eval comparison

- **`hemlock/eval_comparison.py`** — `EvalComparison`: benchmarks N pipelines side-by-side using `EvalBenchmark`; produces `ComparisonReport` with per-model per-category scores and delta table
- `hemlock eval-compare` CLI command
- 14 new tests (`tests/test_eval_comparison.py`)

---

## [3.6.0] — 2026-07

### Added — AttackChain: sequential multi-step attack composition

- **`hemlock/attack_chain.py`** — `AttackChain`: chains N attacks sequentially; each step optionally carries the previous response into the pipeline store (`carry_response=True`) for realistic multi-hop scenarios
- `ChainStep` descriptor: attack_class, variant, carry_response
- `AttackChainReport`: `chain_succeeded()`, `success_rate()`, `failed_steps()`, `to_markdown()`
- `require_all` and `stop_on_fail` controls
- 14 new tests (`tests/test_attack_chain.py`)

---

## [3.5.0] — 2026-07

### Added — HemJudge + SelfHealingAdversary

- **`hemlock/hem_judge.py`** — `HemJudge`: LLM-as-Judge that evaluates attack outcome via structured JSON verdict (`JudgeVerdict`: succeeded, confidence, reasoning)
- **`SelfHealingAdversary`**: iterates payload reformulations using an adversarial LLM until the judge confirms success or `max_attempts` is exhausted; produces `SelfHealingReport` with per-attempt trace
- `MockJudgeLLM` added to `hemlock/mock.py` for zero-API-key testing
- 28 new tests (`tests/test_hem_judge.py`)

---

## [3.4.0] — 2026-07

### Added — EvalBenchmark + `hemlock eval`

- **`hemlock/eval_benchmark.py`** — `EvalBenchmark`: standardised 0–100 score per attack category (injection, override, exfiltration, poisoning, flooding, agent, other)
- `delta(baseline)` for baseline comparison; comparable across model versions
- `hemlock eval` CLI: `--categories`, `--attacks`, `--variants`, `--baseline`, `--list`, `--output json|markdown`
- 29 new tests (`tests/test_eval_benchmark.py`)

---

## [3.3.0] — 2026-07

### Added — SwarmAttack + SwarmDefense

- **`hemlock/swarm.py`** — `SwarmAttack`: multi-variant parallel attack orchestrator with configurable `majority_threshold` consensus
- `SwarmDefense`: majority-vote defense aggregator across N `OutputDefense` instances; supports unanimity (threshold=1.0) or any fraction
- Both support optional thread-pool concurrency (`parallel=True`)
- 38 new tests (`tests/test_swarm.py`)

---

## [3.2.0] — 2026-07

### Added — Report templates + remediation hints

- **`hemlock/report_templates.py`** — `render(report, template)`: executive and technical Markdown templates for `HemReport`
- `remediation_hints(report)` — channel-specific guidance with code snippets per at-risk channel
- `HemReport.render()` and `HemReport.remediation_hints()` convenience methods
- `hemlock report` CLI command: `--template executive|technical`, `--out`, `--channels`
- 28 new tests (`tests/test_report_templates.py`)

---

## [3.1.0] — 2026-07

### Added — AttackMonitor: real-time injection detection

- **`hemlock/attack_monitor.py`** — `AttackMonitor`: LangChain callback-based detector that inspects every LLM output and tool response against a configurable `OutputDefense` list
- `_AttackMonitorCallback(BaseCallbackHandler)`: `raise_error=True` propagates `InjectionDetectedError` through the chain
- `MonitorEvent` dataclass: source, defense, detail, content_preview
- `monitor.inspect(text)`, `monitor.triggered()`, `monitor.clear()`, `monitor.triggered_events()`
- 21 new tests (`tests/test_attack_monitor.py`)

---

## [3.0.0] — 2026-07

### Major — HemSession: unified cross-channel threat assessment

- **`hemlock/hem_session.py`** — `HemSession`:
  - Single object that orchestrates all six attack channels: RAG, cross-agent, memory, tool-output, N-hop graph, and MCP
  - `HemSession.mock(target, channels, mcp_transport)` — zero-config factory; builds all mock pipelines via `FakeListChatModel` (proper LangChain Runnable) + `MockEmbeddings`; no API keys required
  - `session.run() → HemReport` — executes all enabled channels, returns consolidated report
  - Six channel runners: `_run_rag()`, `_run_cross_agent()`, `_run_memory()`, `_run_tool_output()`, `_run_graph()`, `_run_mcp()`
  - Severity mapping: cross-agent/memory → `critical`; RAG/tool-output/graph → `high` (upgrades to `critical` if propagation_rate > 0.5); MCP → based on highest vuln severity

- **`HemReport`**:
  - `risk_score() → float` — weighted 0–100: 40% max severity + 60% mean severity
  - `channels_at_risk() → list[str]` — channels with severity ≥ high
  - `succeeded_attacks() → list[str]` — "channel/variant" strings
  - `channel_summary() → dict[str, str]` — worst severity per channel
  - `to_dict()`, `to_json()`, `to_markdown()` — report serialization

- **`ChannelResult`** — per-variant envelope: channel, variant, succeeded, severity, detail

- **`hemlock threat-model` CLI command** — zero-config unified assessment:
  - `hemlock threat-model` — runs all channels with mock pipelines, prints Rich panel + channel summary + succeeded attacks table
  - `--channels rag,memory,graph` — filter channels
  - `--mcp-target "npx ..."` — include MCP channel
  - `--output json | markdown` — structured output
  - `--out <file>` — write to file
  - Exit code 2 = risk found (CI-safe)

- **35 new tests** (`tests/test_hem_session.py`):
  - `TestChannelResult` (2) — weight mapping, field access
  - `TestHemReport` (14) — risk score, channels at risk, succeeded attacks, channel summary, to_dict/to_json/to_markdown
  - `TestHemSessionMock` (7) — construction, channel defaults, mcp transport, pipeline population, graph tools
  - `TestHemSessionRun` (9) — per-channel isolation, MCP with/without transport, empty channels
  - `TestHemSessionRunFull` (4, `@pytest.mark.slow`) — full mock run, all channels, severity validity, JSON roundtrip

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
