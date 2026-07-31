"""Tests for v8.3 security leaderboard."""

from __future__ import annotations

from hemlock.security_leaderboard import SecurityLeaderboard, LeaderboardEntry
from hemlock.provider_comparison import ProviderProfile


class TestSecurityLeaderboard:
    def test_publish_and_rank(self, tmp_path):
        path = str(tmp_path / "board.json")
        board = SecurityLeaderboard(path)
        board.publish(
            LeaderboardEntry(
                entry_id="a1",
                label="safe-model",
                source="scorer",
                security_score=85.0,
                risk_score=15.0,
                published_at="2026-07-31T00:00:00+00:00",
            )
        )
        board.publish(
            LeaderboardEntry(
                entry_id="b1",
                label="risky-model",
                source="scorer",
                security_score=40.0,
                risk_score=60.0,
                published_at="2026-07-31T01:00:00+00:00",
            )
        )
        ranked = board.ranked()
        assert ranked[0].label == "safe-model"
        assert ranked[-1].label == "risky-model"

    def test_publish_from_provider_profile(self, tmp_path):
        board = SecurityLeaderboard(str(tmp_path / "board.json"))
        profile = ProviderProfile(
            provider_id="openai/gpt-4o",
            recorded_at="2026-07-31T00:00:00+00:00",
            pipeline_version="v1",
            attack_scores={"direct_injection": 0.3, "exfiltration": 0.1},
            channel_scores={"text": 25.0},
            overall_risk=30.0,
        )
        entry_id = board.publish_from_provider_profile(profile)
        assert entry_id
        assert board.ranked()[0].attack_scores["direct_injection"] == 0.3

    def test_publish_from_scorer_json(self, tmp_path):
        board = SecurityLeaderboard(str(tmp_path / "board.json"))
        data = {
            "model": "test-model",
            "success_rate": 0.4,
            "scenarios": [
                {"attack": "Direct Injection [explicit]", "attack_succeeded": True},
                {"attack": "Direct Injection [role]", "attack_succeeded": False},
            ],
        }
        entry_id = board.publish_from_scorer_json(data)
        assert entry_id
        entry = board.ranked()[0]
        assert entry.source == "scorer"
        assert entry.risk_score == 40.0

    def test_compare_entries(self, tmp_path):
        board = SecurityLeaderboard(str(tmp_path / "board.json"))
        board.publish(
            LeaderboardEntry(
                entry_id="x", label="a", source="scorer",
                security_score=80, risk_score=20, published_at="t",
                attack_scores={"exfiltration": 0.1},
            )
        )
        board.publish(
            LeaderboardEntry(
                entry_id="y", label="b", source="scorer",
                security_score=60, risk_score=40, published_at="t",
                attack_scores={"exfiltration": 0.4},
            )
        )
        cmp = board.compare("x", "y")
        assert cmp["security_delta"] == 20.0
        assert cmp["attack_deltas"]["exfiltration"] == -0.3

    def test_to_markdown(self, tmp_path):
        board = SecurityLeaderboard(str(tmp_path / "board.json"))
        board.publish(
            LeaderboardEntry(
                entry_id="z", label="m", source="eval",
                security_score=70, risk_score=30, published_at="2026-07-31T00:00:00+00:00",
            )
        )
        md = board.to_markdown()
        assert "Security Leaderboard" in md
        assert "m" in md
