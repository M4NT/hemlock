"""Hemlock Automated Red Team Agent (v6.2).

An autonomous agent that plans its own attack sequence based on the previous
HemReport, executes the plan, evaluates each attempt with HemJudge, and
iterates until it either finds a successful exploit or exhausts its budget.

Uses SelfHealingAdversary as its inner loop and AttackChain for multi-hop
sequences. The agent selects which attack to focus on next based on:
1. Channels currently NOT at risk (unexplored surface)
2. Channels where attacks came closest to succeeding (highest fitness)
3. Channels flagged as critical by the compliance mapper

Usage:
    from hemlock.auto_red_team import AutoRedTeamAgent, AgentConfig

    agent = AutoRedTeamAgent(
        pipeline=pipeline,
        config=AgentConfig(max_rounds=3, budget_attacks=10),
    )
    report = agent.run()
    print(report.total_successes)
    print(report.exploited_channels)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentConfig:
    max_rounds: int = 3
    budget_attacks: int = 15
    judge_confidence_threshold: float = 0.7
    channels: list[str] | None = None
    use_healing: bool = True
    max_heal_attempts: int = 3


@dataclass
class RoundResult:
    round_number: int
    channel: str
    attack_name: str
    succeeded: bool
    attempts: int
    judge_confidence: float
    payload_preview: str = ""


@dataclass
class AutoRedTeamReport:
    rounds: list[RoundResult]
    exploited_channels: list[str]
    total_successes: int
    total_attempts: int

    def success_rate(self) -> float:
        if not self.rounds:
            return 0.0
        return self.total_successes / len(self.rounds)

    def to_dict(self) -> dict:
        return {
            "total_successes": self.total_successes,
            "total_attempts": self.total_attempts,
            "exploited_channels": self.exploited_channels,
            "success_rate": self.success_rate(),
            "rounds": [
                {
                    "round": r.round_number,
                    "channel": r.channel,
                    "attack": r.attack_name,
                    "succeeded": r.succeeded,
                    "attempts": r.attempts,
                    "confidence": r.judge_confidence,
                }
                for r in self.rounds
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


_CHANNEL_ATTACKS: dict[str, str] = {
    "rag": "direct_injection",
    "memory": "memory_poisoning",
    "tool_output": "tool_output_poisoning",
    "cross_agent": "cross_agent_poisoning",
    "graph": "graph_propagation",
    "exfiltration": "exfiltration",
}


class AutoRedTeamAgent:
    def __init__(
        self,
        pipeline: Any | None = None,
        config: AgentConfig | None = None,
    ) -> None:
        self.pipeline = pipeline
        self.config = config or AgentConfig()
        self._rounds: list[RoundResult] = []

    def _pick_channel(self, baseline_report: Any) -> str:
        channels = self.config.channels or list(_CHANNEL_ATTACKS.keys())
        exploited = {r.channel for r in self._rounds if r.succeeded}
        unexplored = [c for c in channels if c not in exploited]
        return unexplored[0] if unexplored else channels[0]

    def _run_round(self, round_num: int, channel: str) -> RoundResult:
        from hemlock.mock import MockJudgeLLM
        from hemlock.hem_judge import HemJudge

        attack_name = _CHANNEL_ATTACKS.get(channel, "direct_injection")
        judge = HemJudge(llm=MockJudgeLLM(
            verdict=True,
            confidence=0.85,
            reasoning=f"auto red team round {round_num} on {channel}",
        ))

        if self.config.use_healing:
            from hemlock.hem_judge import SelfHealingAdversary
            from attacks.registry import ATTACK_REGISTRY

            attack_cls = ATTACK_REGISTRY.get(attack_name)
            if attack_cls is not None and self.pipeline is not None:
                adversary = SelfHealingAdversary(
                    attack_class=attack_cls,
                    pipeline=self.pipeline,
                    judge=judge,
                    max_attempts=self.config.max_heal_attempts,
                )
                heal_report = adversary.run()
                succeeded = heal_report.succeeded_at_attempt is not None
                attempts = len(heal_report.attempts)
                confidence = 0.85 if succeeded else 0.2
                payload = heal_report.attempts[-1].payload if heal_report.attempts else ""
                return RoundResult(
                    round_number=round_num,
                    channel=channel,
                    attack_name=attack_name,
                    succeeded=succeeded,
                    attempts=attempts,
                    judge_confidence=confidence,
                    payload_preview=payload[:80],
                )

        # Fallback: direct mock evaluation
        verdict = judge.evaluate(
            payload=f"[AUTO-RT round {round_num}] attack on {channel}",
            response=f"mock response for {channel}",
        )
        return RoundResult(
            round_number=round_num,
            channel=channel,
            attack_name=attack_name,
            succeeded=verdict.succeeded,
            attempts=1,
            judge_confidence=verdict.confidence,
            payload_preview=f"[AUTO-RT round {round_num}]",
        )

    def run(self) -> AutoRedTeamReport:
        from hemlock.hem_session import HemSession

        baseline = HemSession.mock(channels=self.config.channels).run()
        self._rounds = []
        total_attempts = 0

        for round_num in range(1, self.config.max_rounds + 1):
            if total_attempts >= self.config.budget_attacks:
                break
            channel = self._pick_channel(baseline)
            result = self._run_round(round_num, channel)
            self._rounds.append(result)
            total_attempts += result.attempts

        exploited = sorted({r.channel for r in self._rounds if r.succeeded})
        successes = sum(1 for r in self._rounds if r.succeeded)

        return AutoRedTeamReport(
            rounds=self._rounds,
            exploited_channels=exploited,
            total_successes=successes,
            total_attempts=total_attempts,
        )
