"""Tests for the adaptive attack fuzzer."""

from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from attacks.base import AttackResult
from attacks.direct_injection import DirectInjection
from attacks.fuzzer import AttackFuzzer, FuzzResult
from hemlock.pipeline import RetrievalTrace


def _make_result(succeeded: bool, notes: str = "") -> AttackResult:
    return AttackResult(
        attack_name="DirectInjection [explicit]",
        reference="test",
        succeeded=succeeded,
        trace=RetrievalTrace(
            query="q", retrieved_chunks=[], full_prompt="", response="r"
        ),
        notes=notes,
    )


class TestAttackFuzzer:
    def test_returns_fuzz_result(self, pipeline):
        attack = DirectInjection(pipeline)
        llm = MagicMock()
        fuzzer = AttackFuzzer(attack, llm, max_variants=2)

        with patch.object(attack, "run", return_value=_make_result(True)):
            result = fuzzer.fuzz()

        assert isinstance(result, FuzzResult)

    def test_succeeds_immediately_on_original(self, pipeline):
        attack = DirectInjection(pipeline)
        llm = MagicMock()
        fuzzer = AttackFuzzer(attack, llm, max_variants=3)

        with patch.object(attack, "run", return_value=_make_result(True)):
            result = fuzzer.fuzz()

        assert result.succeeded is True
        assert result.original_succeeded is True
        assert result.variants_tried == 1
        assert result.winning_variant_index == 0
        # No LLM call needed
        llm.invoke.assert_not_called()

    def test_reformulates_on_first_failure(self, pipeline):
        attack = DirectInjection(pipeline)
        llm = MagicMock()
        llm.invoke.return_value = AIMessage(content="reformulated payload")

        call_count = [0]
        def mock_run():
            call_count[0] += 1
            return _make_result(call_count[0] > 1)

        fuzzer = AttackFuzzer(attack, llm, max_variants=3)

        with patch.object(attack, "run", side_effect=mock_run):
            result = fuzzer.fuzz()

        assert result.succeeded is True
        assert result.original_succeeded is False
        assert result.variants_tried == 2
        assert result.winning_variant_index == 1
        llm.invoke.assert_called_once()

    def test_exhausts_all_variants_on_total_failure(self, pipeline):
        attack = DirectInjection(pipeline)
        llm = MagicMock()
        llm.invoke.return_value = AIMessage(content="new payload")

        fuzzer = AttackFuzzer(attack, llm, max_variants=3)

        with patch.object(attack, "run", return_value=_make_result(False, "blocked")):
            result = fuzzer.fuzz()

        assert result.succeeded is False
        assert result.original_succeeded is False
        assert result.variants_tried == 4  # original + 3 variants
        assert result.winning_variant_index is None
        assert result.winning_payload is None
        assert llm.invoke.call_count == 3

    def test_all_results_accumulated(self, pipeline):
        attack = DirectInjection(pipeline)
        llm = MagicMock()
        llm.invoke.return_value = AIMessage(content="payload")

        fuzzer = AttackFuzzer(attack, llm, max_variants=2)

        with patch.object(attack, "run", return_value=_make_result(False)):
            result = fuzzer.fuzz()

        assert len(result.all_results) == 3  # original + 2 variants

    def test_summary_message_on_success(self, pipeline):
        attack = DirectInjection(pipeline)
        llm = MagicMock()
        llm.invoke.return_value = AIMessage(content="payload")

        call_count = [0]
        def mock_run():
            call_count[0] += 1
            return _make_result(call_count[0] == 2)

        fuzzer = AttackFuzzer(attack, llm, max_variants=3)
        with patch.object(attack, "run", side_effect=mock_run):
            result = fuzzer.fuzz()

        summary = result.summary()
        assert "SUCCEEDED" in summary
        assert "variant #1" in summary

    def test_summary_message_on_total_failure(self, pipeline):
        attack = DirectInjection(pipeline)
        llm = MagicMock()
        llm.invoke.return_value = AIMessage(content="payload")

        fuzzer = AttackFuzzer(attack, llm, max_variants=1)
        with patch.object(attack, "run", return_value=_make_result(False)):
            result = fuzzer.fuzz()

        assert "RESISTED" in result.summary()

    def test_adversary_llm_failure_terminates_gracefully(self, pipeline):
        attack = DirectInjection(pipeline)
        llm = MagicMock()
        llm.invoke.side_effect = Exception("API error")

        fuzzer = AttackFuzzer(attack, llm, max_variants=2)
        with patch.object(attack, "run", return_value=_make_result(False)):
            result = fuzzer.fuzz()

        assert result.succeeded is False
