"""AttackMonitor — real-time injection detection via LangChain callbacks.

Wraps any LangChain chain or agent executor with inline defense checks.
Every LLM output and tool response is inspected against a configurable
set of OutputDefense rules. Triggered events are recorded without
interrupting the pipeline — the monitor is observational by default, but
can be configured to raise on detection.

Usage:
    from hemlock.attack_monitor import AttackMonitor
    from defenses import ExfiltrationGuard, GraphBoundaryGuard

    monitor = AttackMonitor([ExfiltrationGuard(), GraphBoundaryGuard()])

    # Wire into any LangChain chain
    result = chain.invoke(query, config={"callbacks": [monitor.as_callback()]})

    # Inspect findings
    for event in monitor.triggered_events():
        print(event)

    monitor.clear()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from langchain_core.callbacks.base import BaseCallbackHandler
from langchain_core.outputs import LLMResult


# ---------------------------------------------------------------------------
# Event
# ---------------------------------------------------------------------------

@dataclass
class MonitorEvent:
    """A single triggered detection event."""
    source: str     # "llm_output" | "tool_output"
    defense: str    # defense name
    detail: str     # defense detail
    content_preview: str  # first 120 chars of inspected content

    def __repr__(self) -> str:
        return (
            f"<MonitorEvent [{self.source}] defense={self.defense!r} "
            f"detail={self.detail!r}>"
        )


# ---------------------------------------------------------------------------
# Callback handler
# ---------------------------------------------------------------------------

class _AttackMonitorCallback(BaseCallbackHandler):
    """LangChain callback that runs OutputDefenses on every LLM / tool output."""

    def __init__(
        self,
        defenses: list,
        events: list[MonitorEvent],
        raise_on_trigger: bool,
    ) -> None:
        super().__init__()
        self.raise_error       = raise_on_trigger  # let LangChain propagate our exception
        self._defenses         = defenses
        self._events           = events
        self._raise_on_trigger = raise_on_trigger

    def _inspect(self, text: str, source: str) -> None:
        for defense in self._defenses:
            report = defense.validate(text)
            if report.triggered:
                event = MonitorEvent(
                    source=source,
                    defense=defense.name or type(defense).__name__,
                    detail=report.detail,
                    content_preview=text[:120],
                )
                self._events.append(event)
                if self._raise_on_trigger:
                    raise InjectionDetectedError(event)

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        for generations in response.generations:
            for gen in generations:
                text = getattr(gen, "text", None) or (
                    gen.message.content
                    if hasattr(gen, "message") and hasattr(gen.message, "content")
                    else str(gen)
                )
                self._inspect(str(text), "llm_output")

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        self._inspect(str(output), "tool_output")


# ---------------------------------------------------------------------------
# Error
# ---------------------------------------------------------------------------

class InjectionDetectedError(Exception):
    """Raised by AttackMonitor when raise_on_trigger=True and a defense fires."""

    def __init__(self, event: MonitorEvent) -> None:
        self.event = event
        super().__init__(
            f"Injection detected by {event.defense!r} in {event.source}: {event.detail}"
        )


# ---------------------------------------------------------------------------
# AttackMonitor
# ---------------------------------------------------------------------------

class AttackMonitor:
    """Real-time injection monitor — wraps LangChain chains via callbacks.

    Args:
        defenses:          List of ``OutputDefense`` instances to run on every
                           LLM output and tool response.
        raise_on_trigger:  If True, raise ``InjectionDetectedError`` on first
                           detection, interrupting the chain. Default: False
                           (observational mode — records events, does not block).
    """

    def __init__(
        self,
        defenses: list,
        *,
        raise_on_trigger: bool = False,
    ) -> None:
        self._defenses          = defenses
        self._raise_on_trigger  = raise_on_trigger
        self._events: list[MonitorEvent] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def as_callback(self) -> _AttackMonitorCallback:
        """Return a LangChain BaseCallbackHandler wired to this monitor's state."""
        return _AttackMonitorCallback(
            defenses=self._defenses,
            events=self._events,
            raise_on_trigger=self._raise_on_trigger,
        )

    def triggered_events(self) -> list[MonitorEvent]:
        return list(self._events)

    def triggered(self) -> bool:
        return bool(self._events)

    def clear(self) -> None:
        self._events.clear()

    def inspect(self, text: str, source: str = "manual") -> list[MonitorEvent]:
        """Manually inspect a string — useful outside of LangChain chains."""
        before = len(self._events)
        cb = self.as_callback()
        cb._inspect(text, source)
        return self._events[before:]
