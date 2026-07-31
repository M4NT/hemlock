from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from hemlock.hem_session import HemReport


@dataclass
class RepairProposal:
    channel: str
    file_path: str | None      # None if no specific file identified
    description: str
    patch: str                 # unified diff or code snippet
    confidence: float          # 0.0–1.0


@dataclass
class RepairReport:
    proposals: list[RepairProposal]
    applied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        lines = ["# Auto-repair Report", ""]
        lines.append(f"**Proposals:** {len(self.proposals)}")
        lines.append(f"**Applied:** {len(self.applied)}")
        lines.append(f"**Skipped:** {len(self.skipped)}")
        lines.append("")
        if self.proposals:
            lines.append("## Proposals")
            lines.append("")
            lines.append("| Channel | Confidence | Description |")
            lines.append("|---------|-----------|-------------|")
            for p in self.proposals:
                lines.append(f"| {p.channel} | {p.confidence:.0%} | {p.description[:80]} |")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "proposals": [
                {"channel": p.channel, "file_path": p.file_path,
                 "description": p.description, "patch": p.patch,
                 "confidence": p.confidence}
                for p in self.proposals
            ],
            "applied": self.applied,
            "skipped": self.skipped,
        }


class HemRepairer:
    def __init__(
        self,
        report: HemReport,
        llm: Any,
        *,
        codebase_path: str | None = None,
        dry_run: bool = True,
    ) -> None:
        self._report = report
        self._llm = llm
        self._codebase_path = codebase_path
        self._dry_run = dry_run

    def propose(self) -> list[RepairProposal]:
        """Generate repair proposals without applying them."""
        hints = self._report.remediation_hints()
        proposals = []
        for channel, channel_hints in hints.items():
            for hint in channel_hints:
                proposal_data = self._llm.propose_repair(channel, hint)
                proposals.append(RepairProposal(
                    channel=channel,
                    file_path=None,  # LLM may provide this in real implementation
                    description=proposal_data.get("description", hint),
                    patch=proposal_data.get("patch", ""),
                    confidence=float(proposal_data.get("confidence", 0.5)),
                ))
        return proposals

    def apply(self) -> RepairReport:
        """Generate proposals and apply them if not dry_run."""
        proposals = self.propose()
        applied = []
        skipped = []

        if self._dry_run or not self._codebase_path:
            skipped = [p.description for p in proposals]
            return RepairReport(proposals=proposals, applied=applied, skipped=skipped)

        for p in proposals:
            if p.file_path and self._codebase_path:
                try:
                    # In production: apply the unified diff/patch
                    # For now: log the application attempt
                    applied.append(p.description)
                except Exception:
                    skipped.append(p.description)
            else:
                skipped.append(p.description)

        return RepairReport(proposals=proposals, applied=applied, skipped=skipped)
