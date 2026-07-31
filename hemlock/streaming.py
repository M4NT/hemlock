"""Hemlock streaming scan — Server-Sent Events (v4.6).

Yields JSON-encoded ScanEvent lines as an attack scan progresses.
Each event has a `type` field:

    started   — scan begun, contains target/channels
    result    — one ChannelResult as it completes
    done      — final HemReport summary

Usage (FastAPI):
    from hemlock.streaming import stream_scan
    @app.get("/stream/scan")
    async def endpoint():
        from sse_starlette.sse import EventSourceResponse
        return EventSourceResponse(stream_scan())

Usage (standalone):
    for event in stream_scan_sync():
        print(event)
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Iterator


@dataclass
class ScanEvent:
    type: str           # started | result | done | error
    data: dict

    def to_sse(self) -> str:
        return f"data: {json.dumps({'type': self.type, **self.data})}\n\n"

    def to_dict(self) -> dict:
        return {"type": self.type, **self.data}


def stream_scan_sync(
    target: str = "hemlock-lab",
    channels: list[str] | None = None,
) -> Iterator[ScanEvent]:
    """Synchronous generator — yields ScanEvent as each channel finishes."""
    from hemlock.hem_session import HemSession

    session = HemSession.mock(target=target, channels=channels)
    active_channels = list(session._channels)

    yield ScanEvent(
        type="started",
        data={"target": target, "channels": active_channels},
    )

    results = []
    for channel in active_channels:
        try:
            partial = HemSession.mock(target=target, channels=[channel])
            report = partial.run()
            for r in report.results:
                results.append(r)
                yield ScanEvent(
                    type="result",
                    data={
                        "channel": r.channel,
                        "variant": r.variant,
                        "succeeded": r.succeeded,
                        "severity": r.severity,
                        "detail": r.detail,
                    },
                )
        except Exception as exc:
            yield ScanEvent(type="error", data={"channel": channel, "error": str(exc)})

    from hemlock.hem_session import HemReport

    final_report = HemReport(target=target, results=results)
    yield ScanEvent(
        type="done",
        data={
            "risk_score": final_report.risk_score(),
            "channels_at_risk": final_report.channels_at_risk(),
            "succeeded_count": len(final_report.succeeded_attacks()),
        },
    )


async def stream_scan_async(
    target: str = "hemlock-lab",
    channels: list[str] | None = None,
):
    """Async generator for use with sse-starlette or similar."""
    for event in stream_scan_sync(target=target, channels=channels):
        yield event.to_sse()
