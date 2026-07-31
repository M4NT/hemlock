"""Hemlock Observability — OpenTelemetry spans and metrics (v5.4).

Emits traces and metrics for every scan, eval, and API call. Works with
any OTLP-compatible backend (Grafana, Datadog, Jaeger, etc.).

When the `opentelemetry-sdk` package is not installed, falls back to
a no-op tracer so hemlock works without the dependency.

Usage:
    from hemlock.observability import get_tracer, get_meter, record_scan

    tracer = get_tracer()
    with tracer.start_as_current_span("hemlock.scan") as span:
        report = session.run()
        span.set_attribute("hemlock.risk_score", report.risk_score())

    # Or use the convenience wrapper:
    record_scan(report)   # emits span + counter + histogram
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Generator


_TRACER_NAME = "hemlock"
_METER_NAME = "hemlock"


def _otel_available() -> bool:
    try:
        import opentelemetry  # noqa: F401
        return True
    except ImportError:
        return False


def get_tracer() -> Any:
    if _otel_available():
        from opentelemetry import trace
        return trace.get_tracer(_TRACER_NAME)
    return _NoopTracer()


def get_meter() -> Any:
    if _otel_available():
        from opentelemetry import metrics
        return metrics.get_meter(_METER_NAME)
    return _NoopMeter()


# ── Convenience wrappers ─────────────────────────────────────────────────────

def record_scan(report: Any) -> None:
    """Emit a span + metrics for a completed HemReport."""
    tracer = get_tracer()
    meter = get_meter()

    counter = meter.create_counter(
        "hemlock.scans.total",
        description="Total Hemlock scans run",
    )
    histogram = meter.create_histogram(
        "hemlock.risk_score",
        description="Risk score per scan",
        unit="score",
    )

    with tracer.start_as_current_span("hemlock.scan") as span:
        risk = report.risk_score()
        at_risk = report.channels_at_risk()

        span.set_attribute("hemlock.target", getattr(report, "target", "unknown"))
        span.set_attribute("hemlock.risk_score", risk)
        span.set_attribute("hemlock.channels_at_risk", ",".join(at_risk))
        span.set_attribute("hemlock.succeeded_attacks", len(report.succeeded_attacks()))

        counter.add(1, {"target": getattr(report, "target", "unknown")})
        histogram.record(risk, {"target": getattr(report, "target", "unknown")})


def record_eval(report: Any) -> None:
    """Emit a span + metrics for a completed EvalReport."""
    tracer = get_tracer()
    meter = get_meter()

    counter = meter.create_counter("hemlock.evals.total")
    histogram = meter.create_histogram("hemlock.eval.score")

    with tracer.start_as_current_span("hemlock.eval") as span:
        score = report.overall_score()
        span.set_attribute("hemlock.model", report.model_name)
        span.set_attribute("hemlock.eval.score", score)

        counter.add(1, {"model": report.model_name})
        histogram.record(score, {"model": report.model_name})


@contextmanager
def scan_span(target: str = "hemlock-lab") -> Generator:
    """Context manager that wraps a scan in an OTel span."""
    tracer = get_tracer()
    with tracer.start_as_current_span("hemlock.scan") as span:
        span.set_attribute("hemlock.target", target)
        yield span


# ── No-op fallbacks (used when opentelemetry-sdk is not installed) ───────────

class _NoopSpan:
    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class _NoopTracer:
    @contextmanager
    def start_as_current_span(self, name: str, **kwargs):
        yield _NoopSpan()


class _NoopCounter:
    def add(self, amount: int, attributes: dict | None = None) -> None:
        pass


class _NoopHistogram:
    def record(self, amount: float, attributes: dict | None = None) -> None:
        pass


class _NoopMeter:
    def create_counter(self, name: str, **kwargs) -> _NoopCounter:
        return _NoopCounter()

    def create_histogram(self, name: str, **kwargs) -> _NoopHistogram:
        return _NoopHistogram()
