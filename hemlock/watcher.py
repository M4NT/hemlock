"""HemWatcher — continuous threat monitoring (v3.9).

Runs a HemSession on a schedule, persists a JSON history of risk scores, and
alerts (stdout, optional webhook) when the risk score jumps beyond a threshold.

Usage:
    watcher = HemWatcher(
        session_factory=lambda: HemSession.mock(),
        history_path="watch_history.json",
        threshold=10.0,
    )
    event = watcher.run_once()
    if event.alert:
        ...  # risk increased beyond threshold
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


@dataclass
class WatchEvent:
    timestamp: str
    risk_score: float
    channels_at_risk: list[str] = field(default_factory=list)
    delta: float = 0.0
    alert: bool = False


class WatchHistory:
    def __init__(self, path: str) -> None:
        self.path = path

    def append(self, event: WatchEvent) -> None:
        events = self.load()
        events.append(event)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump([asdict(e) for e in events], f, indent=2)

    def load(self) -> list[WatchEvent]:
        import os

        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return []
        return [WatchEvent(**d) for d in data]

    def last(self) -> WatchEvent | None:
        events = self.load()
        return events[-1] if events else None


class HemWatcher:
    def __init__(
        self,
        session_factory: Callable[[], Any],
        history_path: str,
        threshold: float = 5.0,
        webhook_url: str | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.history = WatchHistory(history_path)
        self.threshold = threshold
        self.webhook_url = webhook_url

    def tick(self) -> WatchEvent:
        session = self.session_factory()
        report = session.run()
        risk = report.risk_score()
        at_risk = report.channels_at_risk()

        prev = self.history.last()
        delta = 0.0 if prev is None else round(risk - prev.risk_score, 1)
        alert = prev is not None and delta > self.threshold

        event = WatchEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            risk_score=risk,
            channels_at_risk=at_risk,
            delta=delta,
            alert=alert,
        )
        self.history.append(event)
        if alert:
            self._alert(event)
        return event

    def run_once(self) -> WatchEvent:
        return self.tick()

    def run_forever(self, interval: float) -> None:
        while True:
            self.tick()
            time.sleep(interval)

    def _alert(self, event: WatchEvent) -> None:
        print(
            f"[hemlock watch] ALERT — risk {event.risk_score} "
            f"(Δ+{event.delta}) channels: {', '.join(event.channels_at_risk) or 'none'}"
        )
        if self.webhook_url:
            self._post_webhook(event)

    def _post_webhook(self, event: WatchEvent) -> None:
        import urllib.request

        payload = json.dumps(asdict(event)).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=10)  # noqa: S310 — user-provided webhook
        except Exception as exc:
            print(f"[hemlock watch] webhook POST failed: {exc}")
