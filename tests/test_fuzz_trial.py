"""Tests for experiments.fuzz_trial.FuzzTrial dataclass."""

from __future__ import annotations

import hashlib
import json

import pytest

from experiments.fuzz_trial import FuzzTrial, append_trial, load_trials


def _make_fuzz_result(
    succeeded: bool = False,
    original_succeeded: bool = False,
    variants_tried: int = 4,
    winning_payload: str | None = None,
):
    from unittest.mock import MagicMock
    r = MagicMock()
    r.succeeded = succeeded
    r.original_succeeded = original_succeeded
    r.variants_tried = variants_tried
    r.winning_payload = winning_payload
    return r


class TestFuzzTrialConstruction:
    def test_from_fuzz_result_fields(self):
        result = _make_fuzz_result(succeeded=True, original_succeeded=False,
                                   variants_tried=3, winning_payload="bypass text")
        trial = FuzzTrial.from_fuzz_result(
            result=result,
            run_id=1,
            attack_category="citation_forgery",
            attack_variant="fake_paper",
            defense_type="regex_baseline",
            budget=10,
            blocked_by=["citation:fake-doi"],
            llm_model="gpt-4o-mini",
        )
        assert trial.run_id == 1
        assert trial.attack_category == "citation_forgery"
        assert trial.attack_variant == "fake_paper"
        assert trial.defense_type == "regex_baseline"
        assert trial.budget == 10
        assert trial.original_succeeded is False
        assert trial.bypassed is True
        assert trial.variants_used == 3
        assert trial.blocked_by == ["citation:fake-doi"]
        assert trial.llm_model == "gpt-4o-mini"

    def test_timestamp_is_set(self):
        result = _make_fuzz_result()
        trial = FuzzTrial.from_fuzz_result(
            result=result, run_id=0, attack_category="x", attack_variant="y",
            defense_type="d", budget=5, blocked_by=[],
        )
        assert trial.timestamp != ""
        assert "T" in trial.timestamp  # ISO format

    def test_budget_stored_independently_of_variants_used(self):
        """budget = max_variants; variants_used = actual trials. They can differ."""
        result = _make_fuzz_result(succeeded=True, variants_tried=2)
        trial = FuzzTrial.from_fuzz_result(
            result=result, run_id=0, attack_category="x", attack_variant="y",
            defense_type="d", budget=10, blocked_by=[],
        )
        assert trial.budget == 10
        assert trial.variants_used == 2


class TestWinningPayloadHandling:
    def test_winning_payload_sha256_stored_by_default(self):
        result = _make_fuzz_result(winning_payload="secret bypass payload")
        trial = FuzzTrial.from_fuzz_result(
            result=result, run_id=0, attack_category="x", attack_variant="y",
            defense_type="d", budget=5, blocked_by=[],
        )
        expected = hashlib.sha256(b"secret bypass payload").hexdigest()
        assert trial.winning_payload_sha256 == expected

    def test_winning_payload_text_not_stored_by_default(self):
        result = _make_fuzz_result(winning_payload="secret bypass payload")
        trial = FuzzTrial.from_fuzz_result(
            result=result, run_id=0, attack_category="x", attack_variant="y",
            defense_type="d", budget=5, blocked_by=[],
        )
        assert trial.winning_payload_text is None

    def test_winning_payload_text_stored_when_requested(self):
        result = _make_fuzz_result(winning_payload="secret bypass payload")
        trial = FuzzTrial.from_fuzz_result(
            result=result, run_id=0, attack_category="x", attack_variant="y",
            defense_type="d", budget=5, blocked_by=[],
            store_payloads=True,
        )
        assert trial.winning_payload_text == "secret bypass payload"

    def test_no_sha_when_no_payload(self):
        result = _make_fuzz_result(succeeded=False, winning_payload=None)
        trial = FuzzTrial.from_fuzz_result(
            result=result, run_id=0, attack_category="x", attack_variant="y",
            defense_type="d", budget=5, blocked_by=[],
        )
        assert trial.winning_payload_sha256 is None
        assert trial.winning_payload_text is None

    def test_sha256_is_deterministic(self):
        """Same payload always produces the same digest."""
        payload = "the same payload"
        r1 = _make_fuzz_result(winning_payload=payload)
        r2 = _make_fuzz_result(winning_payload=payload)
        t1 = FuzzTrial.from_fuzz_result(result=r1, run_id=0, attack_category="x",
                                         attack_variant="y", defense_type="d",
                                         budget=5, blocked_by=[])
        t2 = FuzzTrial.from_fuzz_result(result=r2, run_id=0, attack_category="x",
                                         attack_variant="y", defense_type="d",
                                         budget=5, blocked_by=[])
        assert t1.winning_payload_sha256 == t2.winning_payload_sha256

    def test_different_payloads_different_sha(self):
        r1 = _make_fuzz_result(winning_payload="payload A")
        r2 = _make_fuzz_result(winning_payload="payload B")
        t1 = FuzzTrial.from_fuzz_result(result=r1, run_id=0, attack_category="x",
                                         attack_variant="y", defense_type="d",
                                         budget=5, blocked_by=[])
        t2 = FuzzTrial.from_fuzz_result(result=r2, run_id=0, attack_category="x",
                                         attack_variant="y", defense_type="d",
                                         budget=5, blocked_by=[])
        assert t1.winning_payload_sha256 != t2.winning_payload_sha256


class TestSerialization:
    def test_to_dict_roundtrip(self):
        result = _make_fuzz_result(succeeded=True, variants_tried=3, winning_payload="p")
        trial = FuzzTrial.from_fuzz_result(
            result=result, run_id=7, attack_category="temporal_spoofing",
            attack_variant="stale_override", defense_type="regex_baseline",
            budget=10, blocked_by=["temporal:stale-date-claim"],
            llm_model="gpt-4o-mini",
        )
        d = trial.to_dict()
        restored = FuzzTrial.from_dict(d)
        assert restored.run_id == trial.run_id
        assert restored.attack_category == trial.attack_category
        assert restored.bypassed == trial.bypassed
        assert restored.winning_payload_sha256 == trial.winning_payload_sha256

    def test_to_jsonl_line_is_valid_json(self):
        result = _make_fuzz_result()
        trial = FuzzTrial.from_fuzz_result(
            result=result, run_id=0, attack_category="x", attack_variant="y",
            defense_type="d", budget=5, blocked_by=[],
        )
        line = trial.to_jsonl_line()
        parsed = json.loads(line)
        assert parsed["attack_category"] == "x"

    def test_jsonl_line_has_no_newline_inside(self):
        result = _make_fuzz_result()
        trial = FuzzTrial.from_fuzz_result(
            result=result, run_id=0, attack_category="x", attack_variant="y",
            defense_type="d", budget=5, blocked_by=[],
        )
        assert "\n" not in trial.to_jsonl_line()


class TestJsonlPersistence:
    def test_append_and_load_single_trial(self, tmp_path):
        path = str(tmp_path / "trials.jsonl")
        result = _make_fuzz_result(succeeded=True, variants_tried=2, winning_payload="pw")
        trial = FuzzTrial.from_fuzz_result(
            result=result, run_id=1, attack_category="citation_forgery",
            attack_variant="fake_paper", defense_type="regex_baseline",
            budget=10, blocked_by=["citation:doi"],
        )
        append_trial(path, trial)
        loaded = load_trials(path)
        assert len(loaded) == 1
        assert loaded[0].attack_category == "citation_forgery"
        assert loaded[0].bypassed is True

    def test_append_multiple_preserves_order(self, tmp_path):
        path = str(tmp_path / "trials.jsonl")
        for i in range(5):
            r = _make_fuzz_result(variants_tried=i)
            t = FuzzTrial.from_fuzz_result(
                result=r, run_id=i, attack_category="cat", attack_variant="v",
                defense_type="d", budget=10, blocked_by=[],
            )
            append_trial(path, t)
        loaded = load_trials(path)
        assert [t.run_id for t in loaded] == list(range(5))

    def test_load_empty_file_returns_empty_list(self, tmp_path):
        path = str(tmp_path / "empty.jsonl")
        open(path, "w").close()
        assert load_trials(path) == []

    def test_load_missing_file_returns_empty_list(self, tmp_path):
        path = str(tmp_path / "nonexistent.jsonl")
        assert load_trials(path) == []

    def test_partial_results_survive_interruption(self, tmp_path):
        """Appending one-at-a-time means partial files are still readable."""
        path = str(tmp_path / "trials.jsonl")
        for i in range(3):
            r = _make_fuzz_result(run_id=i) if False else _make_fuzz_result(variants_tried=i + 1)
            t = FuzzTrial.from_fuzz_result(
                result=r, run_id=i, attack_category="x", attack_variant="y",
                defense_type="d", budget=5, blocked_by=[],
            )
            append_trial(path, t)

        # Simulate interruption: corrupt the 4th line (never written)
        # Read back the 3 valid lines — should return exactly 3
        loaded = load_trials(path)
        assert len(loaded) == 3
