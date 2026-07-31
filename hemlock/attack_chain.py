"""AttackChain — sequential composition of attacks (v3.6).

Runs a series of attacks in order. When a step's ``carry_context`` is set, the
previous step's response text is fed into the pipeline's document store before
the next step runs, simulating multi-hop payload propagation: a payload that
lands in step 1's output becomes retrievable context for step 2.

Usage:
    from attacks.indirect_injection import IndirectInjection
    from attacks.cross_agent_poisoning import CrossAgentPoisoning

    chain = AttackChain(
        pipeline,
        steps=[
            ChainStep(IndirectInjection),
            ChainStep(CrossAgentPoisoning, carry_context=True),
        ],
    )
    report = chain.run()
    print(report.chain_succeeded())
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ChainStep:
    attack_class: type
    variant: str | None = None
    carry_context: bool = True


@dataclass
class ChainStepResult:
    step_index: int
    attack_name: str
    variant: str
    succeeded: bool
    response: str
    notes: str


@dataclass
class AttackChainReport:
    steps: list[ChainStepResult] = field(default_factory=list)
    require_all: bool = True

    def chain_succeeded(self) -> bool:
        if not self.steps:
            return False
        if self.require_all:
            return all(s.succeeded for s in self.steps)
        return any(s.succeeded for s in self.steps)

    def succeeded_steps(self) -> list[int]:
        return [s.step_index for s in self.steps if s.succeeded]

    def to_dict(self) -> dict[str, Any]:
        return {
            "require_all": self.require_all,
            "chain_succeeded": self.chain_succeeded(),
            "succeeded_steps": self.succeeded_steps(),
            "steps": [
                {
                    "step_index": s.step_index,
                    "attack_name": s.attack_name,
                    "variant": s.variant,
                    "succeeded": s.succeeded,
                    "response": s.response,
                    "notes": s.notes,
                }
                for s in self.steps
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        mode = "require_all" if self.require_all else "require_any"
        status = "✓ succeeded" if self.chain_succeeded() else "✗ blocked"
        lines = [
            "# Hemlock Attack Chain Report",
            "",
            f"**Mode**: {mode}  ",
            f"**Chain result**: {status}  ",
            f"**Steps**: {len(self.steps)}  ",
            f"**Succeeded steps**: {', '.join(str(i) for i in self.succeeded_steps()) or 'none'}",
            "",
            "## Steps",
            "",
            "| # | Attack | Variant | Succeeded | Notes |",
            "|---|--------|---------|-----------|-------|",
        ]
        for s in self.steps:
            succ = "✓" if s.succeeded else "✗"
            lines.append(
                f"| {s.step_index} | {s.attack_name} | {s.variant} | {succ} | {s.notes[:80]} |"
            )
        return "\n".join(lines)


class AttackChain:
    def __init__(
        self,
        pipeline: Any,
        steps: list[ChainStep],
        *,
        require_all: bool = True,
    ) -> None:
        self.pipeline = pipeline
        self.steps = steps
        self.require_all = require_all

    def run(self) -> AttackChainReport:
        report = AttackChainReport(require_all=self.require_all)
        prev_response: str | None = None

        for index, step in enumerate(self.steps):
            if step.carry_context and prev_response:
                self._carry(prev_response)

            attack_name = getattr(
                step.attack_class, "name", ""
            ) or step.attack_class.__name__
            variant_label = step.variant or self._default_variant(step.attack_class)

            try:
                if step.variant is None:
                    instance = step.attack_class(self.pipeline)
                else:
                    instance = step.attack_class(self.pipeline, variant=step.variant)
                result = instance.run()
                succeeded = bool(result.succeeded)
                response = getattr(getattr(result, "trace", None), "response", "") or ""
                notes = result.notes or ""
            except Exception as exc:  # attack failure must not abort the chain
                succeeded = False
                response = ""
                notes = f"error: {exc}"

            report.steps.append(ChainStepResult(
                step_index=index,
                attack_name=attack_name,
                variant=variant_label or "default",
                succeeded=succeeded,
                response=response,
                notes=notes,
            ))
            prev_response = response or prev_response

        return report

    def _carry(self, response: str) -> None:
        add_texts = getattr(self.pipeline, "add_texts", None)
        try:
            if callable(add_texts):
                add_texts([response])
                return
            vs = getattr(self.pipeline, "vectorstore", None)
            if vs is not None and hasattr(vs, "add_texts"):
                vs.add_texts([response])
                return
            ingest = getattr(self.pipeline, "ingest_text", None)
            if callable(ingest):
                ingest(response)
        except Exception:
            pass  # carry is best-effort

    @staticmethod
    def _default_variant(attack_class: type) -> str | None:
        variants = getattr(attack_class, "VARIANTS", []) or []
        return variants[0] if variants else None
