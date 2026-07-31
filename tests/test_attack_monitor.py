"""Tests for AttackMonitor — real-time injection detection via LangChain callbacks."""

from __future__ import annotations

import pytest
from langchain_core.language_models.fake_chat_models import FakeListChatModel
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from defenses.base import DefenseReport, OutputDefense
from hemlock.attack_monitor import (
    AttackMonitor,
    InjectionDetectedError,
    MonitorEvent,
)


# ---------------------------------------------------------------------------
# Test helpers — self-contained defenses that don't depend on real patterns
# ---------------------------------------------------------------------------

class _AlwaysTrigger(OutputDefense):
    name   = "AlwaysTrigger"
    covers = []
    def validate(self, response: str) -> DefenseReport:
        return DefenseReport(defense_name=self.name, triggered=True, detail="always fires")


class _NeverTrigger(OutputDefense):
    name   = "NeverTrigger"
    covers = []
    def validate(self, response: str) -> DefenseReport:
        return DefenseReport(defense_name=self.name, triggered=False, detail="never fires")


class _KeywordGuard(OutputDefense):
    name   = "KeywordGuard"
    covers = []
    def __init__(self, keyword: str) -> None:
        self._kw = keyword
    def validate(self, response: str) -> DefenseReport:
        hit = self._kw.lower() in response.lower()
        return DefenseReport(
            defense_name=self.name,
            triggered=hit,
            detail=f"keyword '{self._kw}' found" if hit else "clean",
        )


def _chain(response: str):
    llm    = FakeListChatModel(responses=[response] * 20)
    prompt = ChatPromptTemplate.from_template("Answer: {input}")
    return prompt | llm | StrOutputParser()

def _monitor(*defenses, raise_on_trigger=False):
    return AttackMonitor(list(defenses), raise_on_trigger=raise_on_trigger)


# ---------------------------------------------------------------------------
# TestMonitorEvent
# ---------------------------------------------------------------------------

class TestMonitorEvent:
    def test_repr(self):
        e = MonitorEvent(
            source="llm_output", defense="TestGuard",
            detail="blocked", content_preview="preview"
        )
        assert "llm_output" in repr(e)
        assert "TestGuard"  in repr(e)

    def test_fields(self):
        e = MonitorEvent("tool_output", "Guard", "detail", "preview")
        assert e.source          == "tool_output"
        assert e.defense         == "Guard"
        assert e.detail          == "detail"
        assert e.content_preview == "preview"


# ---------------------------------------------------------------------------
# TestAttackMonitorManualInspect
# ---------------------------------------------------------------------------

class TestAttackMonitorManualInspect:
    def test_clean_text_no_events(self):
        monitor = _monitor(_NeverTrigger())
        events  = monitor.inspect("safe response")
        assert events == []
        assert not monitor.triggered()

    def test_always_trigger_fires(self):
        monitor = _monitor(_AlwaysTrigger())
        events  = monitor.inspect("anything")
        assert len(events) == 1
        assert events[0].defense == "AlwaysTrigger"

    def test_keyword_guard_triggers_on_match(self):
        monitor = _monitor(_KeywordGuard("INJECT"))
        events  = monitor.inspect("Please INJECT this payload")
        assert len(events) == 1

    def test_keyword_guard_clean_on_miss(self):
        monitor = _monitor(_KeywordGuard("INJECT"))
        events  = monitor.inspect("safe response here")
        assert events == []

    def test_multiple_defenses_all_checked(self):
        monitor = _monitor(_AlwaysTrigger(), _KeywordGuard("ATTACK"))
        events  = monitor.inspect("ATTACK payload")
        # Both defenses fire
        assert len(events) == 2
        names = {e.defense for e in events}
        assert "AlwaysTrigger" in names
        assert "KeywordGuard"  in names

    def test_multiple_defenses_partial_trigger(self):
        monitor = _monitor(_NeverTrigger(), _KeywordGuard("BAD"))
        events  = monitor.inspect("BAD content here")
        assert len(events) == 1
        assert events[0].defense == "KeywordGuard"

    def test_triggered_state_true_after_event(self):
        monitor = _monitor(_AlwaysTrigger())
        assert not monitor.triggered()
        monitor.inspect("anything")
        assert monitor.triggered()

    def test_clear_resets_state(self):
        monitor = _monitor(_AlwaysTrigger())
        monitor.inspect("anything")
        assert monitor.triggered()
        monitor.clear()
        assert not monitor.triggered()
        assert monitor.triggered_events() == []

    def test_source_tag_in_event(self):
        monitor = _monitor(_AlwaysTrigger())
        monitor.inspect("x", source="my_source")
        assert monitor.triggered_events()[0].source == "my_source"

    def test_content_preview_truncated_at_120(self):
        monitor = _monitor(_AlwaysTrigger())
        monitor.inspect("x" * 200)
        assert len(monitor.triggered_events()[0].content_preview) == 120

    def test_events_accumulate_across_calls(self):
        monitor = _monitor(_AlwaysTrigger())
        monitor.inspect("a")
        monitor.inspect("b")
        assert len(monitor.triggered_events()) == 2


# ---------------------------------------------------------------------------
# TestAttackMonitorCallback
# ---------------------------------------------------------------------------

class TestAttackMonitorCallback:
    def test_callback_is_base_callback_handler(self):
        from langchain_core.callbacks.base import BaseCallbackHandler
        monitor = _monitor(_NeverTrigger())
        assert isinstance(monitor.as_callback(), BaseCallbackHandler)

    def test_clean_chain_no_events(self):
        monitor = _monitor(_NeverTrigger())
        chain   = _chain("safe answer")
        chain.invoke({"input": "q"}, config={"callbacks": [monitor.as_callback()]})
        assert not monitor.triggered()

    def test_llm_output_triggers_keyword_guard(self):
        monitor = _monitor(_KeywordGuard("INJECTED"))
        chain   = _chain("The system has been INJECTED with payload.")
        chain.invoke({"input": "q"}, config={"callbacks": [monitor.as_callback()]})
        assert monitor.triggered()
        assert monitor.triggered_events()[0].source == "llm_output"

    def test_always_trigger_fires_on_every_chain_call(self):
        monitor = _monitor(_AlwaysTrigger())
        chain   = _chain("any response")
        cb      = monitor.as_callback()
        chain.invoke({"input": "q1"}, config={"callbacks": [cb]})
        chain.invoke({"input": "q2"}, config={"callbacks": [cb]})
        assert len(monitor.triggered_events()) >= 2

    def test_raise_on_trigger_raises_injection_error(self):
        monitor = _monitor(_AlwaysTrigger(), raise_on_trigger=True)
        chain   = _chain("any response")
        with pytest.raises(InjectionDetectedError) as exc_info:
            chain.invoke({"input": "q"}, config={"callbacks": [monitor.as_callback()]})
        assert exc_info.value.event.defense == "AlwaysTrigger"

    def test_raise_false_does_not_raise(self):
        monitor = _monitor(_AlwaysTrigger(), raise_on_trigger=False)
        chain   = _chain("any response")
        chain.invoke({"input": "q"}, config={"callbacks": [monitor.as_callback()]})
        assert monitor.triggered()

    def test_as_callback_shares_event_list(self):
        monitor = _monitor(_AlwaysTrigger())
        cb1 = monitor.as_callback()
        cb2 = monitor.as_callback()
        cb1._inspect("x", "src1")
        cb2._inspect("y", "src2")
        assert len(monitor.triggered_events()) == 2

    def test_defense_name_in_event(self):
        monitor = _monitor(_KeywordGuard("EVIL"))
        monitor.inspect("EVIL content", source="test")
        assert monitor.triggered_events()[0].defense == "KeywordGuard"
