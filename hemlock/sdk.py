"""Hemlock SDK — stable public Python API (v5.0).

Single entry point for all Hemlock operations. Typed wrappers over the
internal modules with a consistent interface and stable signatures.

Usage:
    from hemlock.sdk import Hemlock

    hem = Hemlock()

    # Threat model
    report = hem.scan()
    print(report.risk_score())
    print(report.to_sarif())

    # Eval benchmark
    eval_report = hem.eval()
    print(eval_report.overall_score())
    print(eval_report.category_scores())

    # Campaign
    campaign_report = hem.campaign(["prod", "staging"])
    print(campaign_report.highest_risk_target())

    # Compliance
    entries = hem.compliance(report, framework="owasp-llm")
    for e in entries:
        print(e.control_id, e.control_name)

    # Streaming
    for event in hem.stream():
        print(event.type, event.data)
"""

from __future__ import annotations

from typing import Any, Iterator


class Hemlock:
    """Stable SDK entry point for Hemlock v5.0.

    Args:
        target:   Label for this assessment target.
        channels: Channels to scan. Default: all non-MCP channels.
        mock:     Use mock mode (no API keys). Default: True.
    """

    def __init__(
        self,
        target: str = "hemlock-lab",
        channels: list[str] | None = None,
        mock: bool = True,
    ) -> None:
        self.target = target
        self.channels = channels
        self.mock = mock

    # ── Core operations ─────────────────────────────────────────────────────

    def scan(self) -> Any:
        """Run a full threat model and return a HemReport."""
        from hemlock.hem_session import HemSession

        session = HemSession.mock(target=self.target, channels=self.channels)
        return session.run()

    def eval(
        self,
        model_name: str = "mock",
        attack_names: list[str] | None = None,
        categories: list[str] | None = None,
    ) -> Any:
        """Run EvalBenchmark and return an EvalReport."""
        from hemlock.eval_benchmark import EvalBenchmark

        bench = EvalBenchmark.from_mock(
            model_name=model_name,
            attack_names=attack_names,
            categories=categories,
        )
        return bench.run()

    def campaign(
        self,
        target_names: list[str],
        max_workers: int = 4,
    ) -> Any:
        """Scan multiple targets in parallel and return a CampaignReport."""
        from hemlock.campaign import Campaign, CampaignTarget

        targets = [
            CampaignTarget(name=name, channels=self.channels)
            for name in target_names
        ]
        return Campaign(targets, max_workers=max_workers).run()

    def compliance(self, report: Any, framework: str = "owasp-llm") -> list:
        """Map a HemReport to compliance entries."""
        from hemlock.compliance import ComplianceMapper

        return ComplianceMapper().map(report, framework)

    def stream(self) -> "Iterator[Any]":
        """Yield ScanEvent objects as each channel completes."""
        from hemlock.streaming import stream_scan_sync

        return stream_scan_sync(target=self.target, channels=self.channels)

    # ── Export helpers ──────────────────────────────────────────────────────

    def to_sarif(self, report: Any) -> str:
        """Convert a HemReport to SARIF 2.1.0 JSON string."""
        from hemlock.sarif_exporter import hem_report_to_sarif, to_sarif_json

        return to_sarif_json(hem_report_to_sarif(report))

    def render(self, report: Any, template: str = "technical") -> str:
        """Render a HemReport as markdown."""
        from hemlock.report_templates import render

        return render(report, template=template)

    # ── Convenience factory ──────────────────────────────────────────────────

    @classmethod
    def mock(
        cls,
        target: str = "hemlock-lab",
        channels: list[str] | None = None,
    ) -> "Hemlock":
        """Return a Hemlock instance pre-configured for mock mode."""
        return cls(target=target, channels=channels, mock=True)

    # ── Version ──────────────────────────────────────────────────────────────

    @staticmethod
    def version() -> str:
        from hemlock import __version__

        return __version__
