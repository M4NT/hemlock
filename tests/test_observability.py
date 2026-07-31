"""Tests for hemlock.observability (v5.4)."""
import pytest
from hemlock.observability import (
    get_tracer,
    get_meter,
    record_scan,
    record_eval,
    scan_span,
    _NoopTracer,
    _NoopMeter,
    _NoopSpan,
    _NoopCounter,
    _NoopHistogram,
)
from hemlock.hem_session import HemSession
from hemlock.eval_benchmark import EvalBenchmark


@pytest.fixture()
def hem_report():
    return HemSession.mock(channels=["rag"]).run()


@pytest.fixture()
def eval_report():
    return EvalBenchmark.from_mock().run()


def test_get_tracer_returns_something():
    tracer = get_tracer()
    assert tracer is not None


def test_get_meter_returns_something():
    meter = get_meter()
    assert meter is not None


def test_noop_tracer_context_manager():
    tracer = _NoopTracer()
    with tracer.start_as_current_span("test") as span:
        span.set_attribute("k", "v")


def test_noop_span_set_attribute():
    span = _NoopSpan()
    span.set_attribute("key", 42)


def test_noop_counter_add():
    c = _NoopCounter()
    c.add(1, {"tag": "v"})


def test_noop_histogram_record():
    h = _NoopHistogram()
    h.record(99.0, {"tag": "v"})


def test_noop_meter_create_counter():
    m = _NoopMeter()
    c = m.create_counter("test.counter")
    assert isinstance(c, _NoopCounter)


def test_noop_meter_create_histogram():
    m = _NoopMeter()
    h = m.create_histogram("test.hist")
    assert isinstance(h, _NoopHistogram)


def test_record_scan_does_not_raise(hem_report):
    record_scan(hem_report)


def test_record_eval_does_not_raise(eval_report):
    record_eval(eval_report)


def test_scan_span_context_manager():
    with scan_span(target="test") as span:
        assert span is not None


def test_scan_span_with_report(hem_report):
    with scan_span(target="test") as span:
        span.set_attribute("hemlock.risk_score", hem_report.risk_score())
