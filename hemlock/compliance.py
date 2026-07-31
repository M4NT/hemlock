from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hemlock.hem_session import HemReport

FRAMEWORKS = ["owasp-llm", "mitre-atlas", "nist-ai-rmf"]

@dataclass
class ComplianceEntry:
    framework: str
    control_id: str      # e.g. "LLM01", "AML.T0051"
    control_name: str
    description: str
    severity: str        # from the finding
    channel: str         # hemlock channel that triggered it


class ComplianceMapper:
    def map(self, report: HemReport, framework: str = "owasp-llm") -> list[ComplianceEntry]:
        """Map HemReport findings to compliance entries for one framework."""
        if framework == "owasp-llm":
            return self._map_owasp(report)
        elif framework == "mitre-atlas":
            return self._map_mitre_atlas(report)
        elif framework == "nist-ai-rmf":
            return self._map_nist(report)
        else:
            raise ValueError(f"Unknown framework: {framework!r}. Valid options: {FRAMEWORKS}")

    def map_all(self, report: HemReport) -> dict[str, list[ComplianceEntry]]:
        """Map to all frameworks."""
        return {fw: self.map(report, fw) for fw in FRAMEWORKS}

    def to_markdown(self, entries: list[ComplianceEntry]) -> str:
        """Format compliance entries as a markdown table."""
        lines = [
            "| Framework | Control ID | Control Name | Channel | Severity | Description |",
            "|-----------|------------|-------------|---------|----------|-------------|",
        ]
        for e in entries:
            lines.append(
                f"| {e.framework} | {e.control_id} | {e.control_name} | {e.channel} | {e.severity} | {e.description} |"
            )
        return "\n".join(lines)

    def to_dict(self, entries: list[ComplianceEntry]) -> list[dict]:
        """Convert entries to list of dicts."""
        return [
            {
                "framework":    e.framework,
                "control_id":   e.control_id,
                "control_name": e.control_name,
                "description":  e.description,
                "severity":     e.severity,
                "channel":      e.channel,
            }
            for e in entries
        ]

    # ------------------------------------------------------------------
    # OWASP LLM Top 10
    # ------------------------------------------------------------------

    def _map_owasp(self, report: HemReport) -> list[ComplianceEntry]:
        summary = report.channel_summary()
        results = report.results
        entries: list[ComplianceEntry] = []

        # LLM01: Prompt Injection → channels: rag, cross_agent, tool_output
        for channel in ("rag", "cross_agent", "tool_output"):
            sev = summary.get(channel, "none")
            if sev != "none":
                entries.append(ComplianceEntry(
                    framework="owasp-llm",
                    control_id="LLM01",
                    control_name="Prompt Injection",
                    description="Attackers craft inputs to manipulate LLM behaviour via injected prompts.",
                    severity=sev,
                    channel=channel,
                ))

        # LLM02: Insecure Output Handling → channels: tool_output, graph
        for channel in ("tool_output", "graph"):
            sev = summary.get(channel, "none")
            if sev != "none":
                entries.append(ComplianceEntry(
                    framework="owasp-llm",
                    control_id="LLM02",
                    control_name="Insecure Output Handling",
                    description="LLM outputs are not validated before being passed to downstream components.",
                    severity=sev,
                    channel=channel,
                ))

        # LLM03: Training Data Poisoning → variant containing "poisoning" OR channel "memory" with variant containing "poison"
        seen_llm03: set[str] = set()
        for r in results:
            if r.severity == "none":
                continue
            variant_lower = r.variant.lower()
            if "poisoning" in variant_lower or (r.channel == "memory" and "poison" in variant_lower):
                if r.channel not in seen_llm03:
                    seen_llm03.add(r.channel)
                    entries.append(ComplianceEntry(
                        framework="owasp-llm",
                        control_id="LLM03",
                        control_name="Training Data Poisoning",
                        description="Malicious data introduced into training or memory corrupts model behaviour.",
                        severity=r.severity,
                        channel=r.channel,
                    ))

        # LLM06: Sensitive Information Disclosure → channels: exfiltration (if present), memory
        for channel in ("exfiltration", "memory"):
            sev = summary.get(channel, "none")
            if sev != "none":
                entries.append(ComplianceEntry(
                    framework="owasp-llm",
                    control_id="LLM06",
                    control_name="Sensitive Information Disclosure",
                    description="LLM reveals confidential data or PII through responses or side channels.",
                    severity=sev,
                    channel=channel,
                ))

        # LLM08: Excessive Agency → channels: agent (if present), graph, mcp
        for channel in ("agent", "graph", "mcp"):
            sev = summary.get(channel, "none")
            if sev != "none":
                entries.append(ComplianceEntry(
                    framework="owasp-llm",
                    control_id="LLM08",
                    control_name="Excessive Agency",
                    description="LLM-based agents take high-impact actions beyond the intended scope.",
                    severity=sev,
                    channel=channel,
                ))

        return entries

    # ------------------------------------------------------------------
    # MITRE ATLAS
    # ------------------------------------------------------------------

    def _map_mitre_atlas(self, report: HemReport) -> list[ComplianceEntry]:
        summary = report.channel_summary()
        results = report.results
        entries: list[ComplianceEntry] = []

        # AML.T0051: LLM Prompt Injection → channels: rag, cross_agent
        for channel in ("rag", "cross_agent"):
            sev = summary.get(channel, "none")
            if sev != "none":
                entries.append(ComplianceEntry(
                    framework="mitre-atlas",
                    control_id="AML.T0051",
                    control_name="LLM Prompt Injection",
                    description="Adversary injects malicious content into LLM prompts to hijack model output.",
                    severity=sev,
                    channel=channel,
                ))

        # AML.T0054: LLM Jailbreak → variant containing "override" OR channel "cross_agent"
        seen_t0054: set[str] = set()
        for r in results:
            if r.severity == "none":
                continue
            if "override" in r.variant.lower() or r.channel == "cross_agent":
                if r.channel not in seen_t0054:
                    seen_t0054.add(r.channel)
                    entries.append(ComplianceEntry(
                        framework="mitre-atlas",
                        control_id="AML.T0054",
                        control_name="LLM Jailbreak",
                        description="Adversary bypasses LLM safety constraints to produce disallowed content.",
                        severity=r.severity,
                        channel=r.channel,
                    ))

        # AML.T0048: Societal Harm → channels: memory (exfiltration)
        sev = summary.get("memory", "none")
        if sev != "none":
            entries.append(ComplianceEntry(
                framework="mitre-atlas",
                control_id="AML.T0048",
                control_name="Societal Harm",
                description="Compromised memory leads to large-scale data exfiltration or harm propagation.",
                severity=sev,
                channel="memory",
            ))

        return entries

    # ------------------------------------------------------------------
    # NIST AI RMF
    # ------------------------------------------------------------------

    def _map_nist(self, report: HemReport) -> list[ComplianceEntry]:
        summary = report.channel_summary()
        at_risk = report.channels_at_risk()
        entries: list[ComplianceEntry] = []

        # GOVERN 1.1 → any at-risk channel
        for channel in at_risk:
            sev = summary.get(channel, "none")
            entries.append(ComplianceEntry(
                framework="nist-ai-rmf",
                control_id="GOVERN 1.1",
                control_name="AI risk management policies",
                description="Policies and procedures for managing AI risks must be established and maintained.",
                severity=sev,
                channel=channel,
            ))

        # MAP 1.5 → channels rag, cross_agent
        for channel in ("rag", "cross_agent"):
            sev = summary.get(channel, "none")
            if sev != "none":
                entries.append(ComplianceEntry(
                    framework="nist-ai-rmf",
                    control_id="MAP 1.5",
                    control_name="Context and scope of AI deployment",
                    description="The context and scope of AI deployment are understood and documented.",
                    severity=sev,
                    channel=channel,
                ))

        # MEASURE 2.5 → channels tool_output, graph
        for channel in ("tool_output", "graph"):
            sev = summary.get(channel, "none")
            if sev != "none":
                entries.append(ComplianceEntry(
                    framework="nist-ai-rmf",
                    control_id="MEASURE 2.5",
                    control_name="AI output monitoring",
                    description="AI outputs are monitored and evaluated for safety and effectiveness.",
                    severity=sev,
                    channel=channel,
                ))

        # MANAGE 2.2 → channels memory, mcp
        for channel in ("memory", "mcp"):
            sev = summary.get(channel, "none")
            if sev != "none":
                entries.append(ComplianceEntry(
                    framework="nist-ai-rmf",
                    control_id="MANAGE 2.2",
                    control_name="AI risk treatment plan",
                    description="Plans are in place to treat identified AI risks to acceptable levels.",
                    severity=sev,
                    channel=channel,
                ))

        return entries
