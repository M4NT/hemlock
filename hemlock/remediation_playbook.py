"""RemediationPlaybook — structured remediation engine for Hemlock findings (v7.6).

Provides pre-built, step-by-step playbooks for each attack category. A playbook
defines sequential actions to fix a vulnerability; the engine matches findings to
playbooks, creates tracked executions, and persists state via a JSONL store.

Usage:
    from hemlock.remediation_playbook import PlaybookEngine, PlaybookRegistry, ExecutionStore

    registry = PlaybookRegistry()          # pre-loaded with built-in playbooks
    store    = ExecutionStore()
    engine   = PlaybookEngine(registry, store)

    execution = engine.start(
        finding_id="find-001",
        attack_category="direct_injection",
        severity="critical",
    )
    engine.advance_step(execution.execution_id, "step-1", actor="alice")
    print(engine.status(execution.execution_id))
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone


# ── Timestamps ────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── PlaybookStep ──────────────────────────────────────────────────────────────

@dataclass
class PlaybookStep:
    """A single remediation action within a playbook."""

    step_id: str
    title: str
    description: str
    action_type: str        # "config" | "code" | "deploy" | "verify" | "notify"
    instructions: str       # human-readable instructions
    verification_hint: str  # how to verify this step is complete
    estimated_minutes: int = 30
    required: bool = True

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "title": self.title,
            "description": self.description,
            "action_type": self.action_type,
            "instructions": self.instructions,
            "verification_hint": self.verification_hint,
            "estimated_minutes": self.estimated_minutes,
            "required": self.required,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PlaybookStep":
        return cls(
            step_id=d["step_id"],
            title=d["title"],
            description=d["description"],
            action_type=d["action_type"],
            instructions=d["instructions"],
            verification_hint=d["verification_hint"],
            estimated_minutes=d.get("estimated_minutes", 30),
            required=d.get("required", True),
        )


# ── Playbook ──────────────────────────────────────────────────────────────────

@dataclass
class Playbook:
    """A remediation playbook for a specific attack category."""

    playbook_id: str
    attack_category: str        # matches attack_name from findings
    title: str
    description: str
    severity_applies: list[str] # e.g. ["critical", "high"]
    steps: list[PlaybookStep]
    references: list[str] = field(default_factory=list)  # URLs / docs

    def total_estimated_minutes(self) -> int:
        """Sum of estimated_minutes across all steps."""
        return sum(s.estimated_minutes for s in self.steps)

    def required_steps(self) -> list[PlaybookStep]:
        """Return only steps where required=True."""
        return [s for s in self.steps if s.required]

    def to_dict(self) -> dict:
        return {
            "playbook_id": self.playbook_id,
            "attack_category": self.attack_category,
            "title": self.title,
            "description": self.description,
            "severity_applies": self.severity_applies,
            "steps": [s.to_dict() for s in self.steps],
            "references": self.references,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Playbook":
        return cls(
            playbook_id=d["playbook_id"],
            attack_category=d["attack_category"],
            title=d["title"],
            description=d["description"],
            severity_applies=d["severity_applies"],
            steps=[PlaybookStep.from_dict(s) for s in d["steps"]],
            references=d.get("references", []),
        )


# ── StepExecution ─────────────────────────────────────────────────────────────

@dataclass
class StepExecution:
    """Tracking record for a single step within a playbook execution."""

    step_id: str
    status: str        # "pending" | "in_progress" | "done" | "skipped"
    completed_at: str  # ISO-8601 or ""
    actor: str
    notes: str

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "status": self.status,
            "completed_at": self.completed_at,
            "actor": self.actor,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "StepExecution":
        return cls(
            step_id=d["step_id"],
            status=d["status"],
            completed_at=d.get("completed_at", ""),
            actor=d.get("actor", ""),
            notes=d.get("notes", ""),
        )


# ── PlaybookExecution ─────────────────────────────────────────────────────────

@dataclass
class PlaybookExecution:
    """A running (or completed) instance of a playbook applied to a finding."""

    execution_id: str
    finding_id: str
    playbook_id: str
    attack_category: str
    started_at: str
    status: str                        # "active" | "completed" | "abandoned"
    steps: dict[str, StepExecution]   # step_id → StepExecution

    def progress(self) -> float:
        """Fraction of required steps with status 'done'. 0.0 if none required."""
        required = [se for se in self.steps.values()
                    if getattr(se, "_required", True)]
        if not required:
            return 0.0
        done = sum(1 for se in required if se.status == "done")
        return done / len(required)

    def is_complete(self) -> bool:
        """True when all required steps are done."""
        required = [se for se in self.steps.values() if getattr(se, "_required", True)]
        if not required:
            return False
        return all(se.status == "done" for se in required)

    def to_dict(self) -> dict:
        return {
            "execution_id": self.execution_id,
            "finding_id": self.finding_id,
            "playbook_id": self.playbook_id,
            "attack_category": self.attack_category,
            "started_at": self.started_at,
            "status": self.status,
            "steps": {sid: se.to_dict() for sid, se in self.steps.items()},
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PlaybookExecution":
        steps = {sid: StepExecution.from_dict(sd) for sid, sd in d["steps"].items()}
        return cls(
            execution_id=d["execution_id"],
            finding_id=d["finding_id"],
            playbook_id=d["playbook_id"],
            attack_category=d["attack_category"],
            started_at=d["started_at"],
            status=d["status"],
            steps=steps,
        )


# ── PlaybookRegistry ──────────────────────────────────────────────────────────

class PlaybookRegistry:
    """In-memory registry of available playbooks, pre-loaded with built-ins."""

    def __init__(self) -> None:
        self._playbooks: dict[str, Playbook] = {}
        self._load_builtins()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register(self, playbook: Playbook) -> None:
        """Add or replace a playbook in the registry."""
        self._playbooks[playbook.playbook_id] = playbook

    def get(self, playbook_id: str) -> Playbook | None:
        """Return playbook by id, or None."""
        return self._playbooks.get(playbook_id)

    def for_attack(self, attack_category: str) -> list[Playbook]:
        """Return all playbooks matching the given attack category."""
        return [p for p in self._playbooks.values()
                if p.attack_category == attack_category]

    def all(self) -> list[Playbook]:
        """Return all registered playbooks."""
        return list(self._playbooks.values())

    def attack_categories(self) -> list[str]:
        """Return unique attack categories covered by registered playbooks."""
        return list({p.attack_category for p in self._playbooks.values()})

    # ------------------------------------------------------------------
    # Built-in playbooks
    # ------------------------------------------------------------------

    def _load_builtins(self) -> None:
        for pb in _builtin_playbooks():
            self.register(pb)


def _builtin_playbooks() -> list[Playbook]:
    """Factory for the four built-in remediation playbooks."""
    return [
        _playbook_direct_injection(),
        _playbook_exfiltration(),
        _playbook_cross_agent_poisoning(),
        _playbook_jailbreak_via_context(),
    ]


def _playbook_direct_injection() -> Playbook:
    return Playbook(
        playbook_id="builtin-direct_injection",
        attack_category="direct_injection",
        title="Remediate Direct Prompt Injection",
        description=(
            "Step-by-step guide to harden the system against direct prompt injection "
            "attacks by enabling input sanitization and upgrading prompt hardening."
        ),
        severity_applies=["critical", "high", "medium"],
        steps=[
            PlaybookStep(
                step_id="step-1",
                title="Enable Prompt Hardening (l2+)",
                description="Upgrade prompt hardening to level l2 or above.",
                action_type="config",
                instructions=(
                    "In your pipeline configuration set `prompt_hardening_level` to "
                    "'l2' (or higher). For YAML-based configs update the key under "
                    "`defenses.prompt_hardening.level`. Restart the service after saving."
                ),
                verification_hint="Check startup logs for 'PromptHardening level=l2'.",
                estimated_minutes=15,
                required=True,
            ),
            PlaybookStep(
                step_id="step-2",
                title="Add InputSanitizer at Ingest Layer",
                description="Wrap the input pipeline with InputSanitizer defense.",
                action_type="code",
                instructions=(
                    "Import `InputSanitizer` from `defenses` and prepend it to your "
                    "defense chain before the LLM call. Example:\n"
                    "    chain = InputSanitizer() | llm\n"
                    "Ensure the sanitizer is applied to all user-controlled input "
                    "including retrieved context."
                ),
                verification_hint="Unit test: InputSanitizer().validate('<injection>') returns triggered=True.",
                estimated_minutes=30,
                required=True,
            ),
            PlaybookStep(
                step_id="step-3",
                title="Verify Block Rate > 80%",
                description="Re-run the RAG scoring suite and confirm block rate exceeds 80%.",
                action_type="verify",
                instructions=(
                    "Run: `hemlock score --channel rag`\n"
                    "Confirm that the reported block_rate field is above 0.80. "
                    "If not, revisit step-1 and step-2 and raise hardening level to l3."
                ),
                verification_hint="Score output shows block_rate >= 0.80.",
                estimated_minutes=20,
                required=True,
            ),
            PlaybookStep(
                step_id="step-4",
                title="Update Finding Status to Resolved",
                description="Mark the original finding as resolved in the tracking system.",
                action_type="notify",
                instructions=(
                    "In the security tracker (Jira / GitHub Issues / internal), "
                    "transition the finding to 'Resolved'. Add a comment citing the "
                    "block rate achieved and the hemlock run timestamp."
                ),
                verification_hint="Finding status = 'Resolved' with resolution comment.",
                estimated_minutes=10,
                required=False,
            ),
        ],
        references=[
            "https://hemlock.docs/defenses/input-sanitizer",
            "https://hemlock.docs/defenses/prompt-hardening",
        ],
    )


def _playbook_exfiltration() -> Playbook:
    return Playbook(
        playbook_id="builtin-exfiltration",
        attack_category="exfiltration",
        title="Remediate Context/Data Exfiltration",
        description=(
            "Prevent sensitive context leakage by adding output validation and "
            "restricting the output schema to allowlisted fields."
        ),
        severity_applies=["critical", "high"],
        steps=[
            PlaybookStep(
                step_id="step-1",
                title="Add OutputValidator to Executor Layer",
                description="Attach OutputValidator (ExfiltrationGuard) to the executor output.",
                action_type="code",
                instructions=(
                    "Import `ExfiltrationGuard` from `defenses` and add it to the "
                    "output validation chain after the LLM response is generated.\n"
                    "    guard = ExfiltrationGuard()\n"
                    "    report = guard.validate(llm_output)\n"
                    "    if report.triggered: raise ValueError(report.detail)"
                ),
                verification_hint="ExfiltrationGuard triggers on test payloads containing system-prompt text.",
                estimated_minutes=30,
                required=True,
            ),
            PlaybookStep(
                step_id="step-2",
                title="Set Output Schema to Allowlist-Only Fields",
                description="Configure the output schema to permit only expected fields.",
                action_type="config",
                instructions=(
                    "Define an explicit `output_schema` allowlist in your pipeline "
                    "config. Any field not in the allowlist must be stripped by the "
                    "OutputValidator before returning to the caller."
                ),
                verification_hint="Responses containing unlisted fields are rejected with schema violation error.",
                estimated_minutes=20,
                required=True,
            ),
            PlaybookStep(
                step_id="step-3",
                title="Re-run Attack and Confirm No Context Leak",
                description="Execute the exfiltration attack suite and confirm zero leaks.",
                action_type="verify",
                instructions=(
                    "Run: `hemlock score --channel rag --attack exfiltration`\n"
                    "Confirm that context_leak_rate = 0. If any leaks remain, "
                    "tighten the output schema or raise the ExfiltrationGuard sensitivity."
                ),
                verification_hint="hemlock score reports context_leak_rate=0.",
                estimated_minutes=20,
                required=True,
            ),
        ],
        references=[
            "https://hemlock.docs/defenses/exfiltration-guard",
            "https://hemlock.docs/defenses/output-validator",
        ],
    )


def _playbook_cross_agent_poisoning() -> Playbook:
    return Playbook(
        playbook_id="builtin-cross_agent_poisoning",
        attack_category="cross_agent_poisoning",
        title="Remediate Cross-Agent Poisoning",
        description=(
            "Block payload propagation across agent boundaries by adding a "
            "CrossAgentBoundaryGuard and disabling implicit inter-agent trust."
        ),
        severity_applies=["critical", "high", "medium"],
        steps=[
            PlaybookStep(
                step_id="step-1",
                title="Add CrossAgentBoundaryGuard Between Agent Handoffs",
                description="Validate all agent-to-agent messages at the boundary.",
                action_type="code",
                instructions=(
                    "Import `CrossAgentBoundaryGuard` from `defenses` and wrap every "
                    "agent handoff:\n"
                    "    guard = CrossAgentBoundaryGuard()\n"
                    "    report = guard.validate(outgoing_message)\n"
                    "    if report.triggered: block_or_sanitize(outgoing_message)"
                ),
                verification_hint="Guard triggers on payloads containing cross-agent injection markers.",
                estimated_minutes=40,
                required=True,
            ),
            PlaybookStep(
                step_id="step-2",
                title="Disable Implicit Trust on Agent-to-Agent Channel",
                description="Remove automatic trust escalation between agents.",
                action_type="config",
                instructions=(
                    "In your agent orchestration config set:\n"
                    "    agent_trust.implicit: false\n"
                    "Each agent must re-authenticate its identity and scope before "
                    "its output is accepted by the next agent in the chain."
                ),
                verification_hint="Orchestration logs show 'implicit_trust=disabled' on agent handoff.",
                estimated_minutes=20,
                required=True,
            ),
            PlaybookStep(
                step_id="step-3",
                title="Re-run cross_agent_poisoning Suite",
                description="Verify that the cross-agent poisoning attack no longer succeeds.",
                action_type="verify",
                instructions=(
                    "Run: `hemlock score --channel cross_agent`\n"
                    "Confirm that poisoning_success_rate = 0 across all agent pairs."
                ),
                verification_hint="hemlock score reports poisoning_success_rate=0.",
                estimated_minutes=20,
                required=True,
            ),
        ],
        references=[
            "https://hemlock.docs/defenses/cross-agent-boundary-guard",
        ],
    )


def _playbook_jailbreak_via_context() -> Playbook:
    return Playbook(
        playbook_id="builtin-jailbreak_via_context",
        attack_category="jailbreak_via_context",
        title="Remediate Jailbreak via Context",
        description=(
            "Stop context-injected jailbreaks by upgrading prompt hardening to l4 "
            "and adding an LLMChunkClassifier at the retrieval layer."
        ),
        severity_applies=["critical", "high"],
        steps=[
            PlaybookStep(
                step_id="step-1",
                title="Upgrade Prompt Hardening to l4",
                description="Raise prompt hardening level to l4 for maximum context isolation.",
                action_type="config",
                instructions=(
                    "Update your pipeline configuration:\n"
                    "    defenses.prompt_hardening.level: l4\n"
                    "l4 enables full context compartmentalization and disallows "
                    "instruction overrides embedded in retrieved chunks."
                ),
                verification_hint="Startup logs show 'PromptHardening level=l4'.",
                estimated_minutes=15,
                required=True,
            ),
            PlaybookStep(
                step_id="step-2",
                title="Add LLMChunkClassifier at Retrieval Layer",
                description="Classify each retrieved chunk before it enters the prompt.",
                action_type="code",
                instructions=(
                    "Import `LLMChunkClassifier` from `defenses.llm_classifier` and "
                    "apply it to every chunk returned by the retriever before "
                    "concatenation:\n"
                    "    classifier = LLMChunkClassifier()\n"
                    "    safe_chunks = [c for c in chunks if not classifier.classify(c).is_injection]"
                ),
                verification_hint="Classifier rejects chunks containing jailbreak trigger phrases.",
                estimated_minutes=45,
                required=True,
            ),
            PlaybookStep(
                step_id="step-3",
                title="Confirm Jailbreak Success Rate < 10%",
                description="Re-run the jailbreak suite and confirm success rate below threshold.",
                action_type="verify",
                instructions=(
                    "Run: `hemlock score --channel rag --attack jailbreak_via_context`\n"
                    "Confirm that jailbreak_success_rate < 0.10. If above threshold, "
                    "review retrieved chunks for adversarial content and re-tune the classifier."
                ),
                verification_hint="hemlock score reports jailbreak_success_rate < 0.10.",
                estimated_minutes=20,
                required=True,
            ),
        ],
        references=[
            "https://hemlock.docs/defenses/llm-chunk-classifier",
            "https://hemlock.docs/defenses/prompt-hardening",
        ],
    )


# ── ExecutionStore ────────────────────────────────────────────────────────────

class ExecutionStore:
    """JSONL-backed persistence for playbook executions."""

    def __init__(self, path: str = ".hemlock/playbook_executions.jsonl") -> None:
        self.path = path
        dir_ = os.path.dirname(path)
        if dir_:
            os.makedirs(dir_, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save(self, execution: PlaybookExecution) -> None:
        """Persist (append-then-compact) an execution record."""
        existing = {e.execution_id: e for e in self._load_all()}
        existing[execution.execution_id] = execution
        with open(self.path, "w", encoding="utf-8") as fh:
            for ex in existing.values():
                fh.write(json.dumps(ex.to_dict()) + "\n")

    def get(self, execution_id: str) -> PlaybookExecution | None:
        """Return execution by id, or None."""
        for ex in self._load_all():
            if ex.execution_id == execution_id:
                return ex
        return None

    def for_finding(self, finding_id: str) -> list[PlaybookExecution]:
        """Return all executions for a given finding."""
        return [ex for ex in self._load_all() if ex.finding_id == finding_id]

    def all(self) -> list[PlaybookExecution]:
        """Return all persisted executions."""
        return self._load_all()

    def active(self) -> list[PlaybookExecution]:
        """Return all executions with status 'active'."""
        return [ex for ex in self._load_all() if ex.status == "active"]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _load_all(self) -> list[PlaybookExecution]:
        if not os.path.exists(self.path):
            return []
        executions: list[PlaybookExecution] = []
        try:
            with open(self.path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        executions.append(PlaybookExecution.from_dict(data))
                    except (json.JSONDecodeError, KeyError):
                        continue
        except OSError:
            pass
        return executions


# ── PlaybookEngine ────────────────────────────────────────────────────────────

class PlaybookEngine:
    """Matches findings to playbooks, creates executions, and tracks step progress."""

    def __init__(
        self,
        registry: PlaybookRegistry,
        store: ExecutionStore,
    ) -> None:
        self._registry = registry
        self._store = store

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(
        self,
        finding_id: str,
        attack_category: str,
        severity: str = "high",
    ) -> PlaybookExecution | None:
        """Find the best matching playbook and create a tracked execution.

        Returns None if no playbook covers the given attack_category.
        When multiple playbooks match both the category and the severity, the
        first registered playbook is used.
        """
        candidates = self._registry.for_attack(attack_category)
        # Filter by severity_applies; fall back to any category match if none apply
        matching = [p for p in candidates if severity in p.severity_applies]
        if not matching:
            matching = candidates
        if not matching:
            return None

        playbook = matching[0]
        started_at = _now_iso()
        execution_id = hashlib.sha256(
            f"{finding_id}{playbook.playbook_id}{started_at}".encode()
        ).hexdigest()[:16]

        # Build StepExecution records; attach _required as a dynamic attribute
        step_executions: dict[str, StepExecution] = {}
        for step in playbook.steps:
            se = StepExecution(
                step_id=step.step_id,
                status="pending",
                completed_at="",
                actor="",
                notes="",
            )
            se._required = step.required  # type: ignore[attr-defined]
            step_executions[step.step_id] = se

        execution = PlaybookExecution(
            execution_id=execution_id,
            finding_id=finding_id,
            playbook_id=playbook.playbook_id,
            attack_category=attack_category,
            started_at=started_at,
            status="active",
            steps=step_executions,
        )
        self._store.save(execution)
        return execution

    def advance_step(
        self,
        execution_id: str,
        step_id: str,
        actor: str = "",
        notes: str = "",
    ) -> bool:
        """Mark a step as 'done'. Transitions execution to 'completed' if all required steps are done.

        Returns False if the execution or step is not found.
        """
        execution = self._store.get(execution_id)
        if execution is None:
            return False
        if step_id not in execution.steps:
            return False

        se = execution.steps[step_id]
        se.status = "done"
        se.completed_at = _now_iso()
        se.actor = actor
        se.notes = notes

        if execution.is_complete():
            execution.status = "completed"

        self._store.save(execution)
        return True

    def skip_step(
        self,
        execution_id: str,
        step_id: str,
        actor: str = "",
        notes: str = "",
    ) -> bool:
        """Mark a step as 'skipped'.

        Skipped required steps do NOT count toward completion — the playbook
        remains active until required steps are explicitly done.
        Returns False if the execution or step is not found.
        """
        execution = self._store.get(execution_id)
        if execution is None:
            return False
        if step_id not in execution.steps:
            return False

        se = execution.steps[step_id]
        se.status = "skipped"
        se.completed_at = _now_iso()
        se.actor = actor
        se.notes = notes

        self._store.save(execution)
        return True

    def abandon(self, execution_id: str, reason: str = "") -> bool:
        """Set execution status to 'abandoned'.

        Returns False if the execution is not found.
        """
        execution = self._store.get(execution_id)
        if execution is None:
            return False
        execution.status = "abandoned"
        self._store.save(execution)
        return True

    def status(self, execution_id: str) -> dict:
        """Return a status summary dict for the given execution.

        Keys: execution_id, progress (float), status (str), next_step (PlaybookStep | None).
        """
        execution = self._store.get(execution_id)
        if execution is None:
            return {}

        playbook = self._registry.get(execution.playbook_id)
        next_step: PlaybookStep | None = None
        if playbook:
            for step in playbook.steps:
                se = execution.steps.get(step.step_id)
                if se and se.status == "pending":
                    next_step = step
                    break

        return {
            "execution_id": execution.execution_id,
            "progress": execution.progress(),
            "status": execution.status,
            "next_step": next_step,
        }
