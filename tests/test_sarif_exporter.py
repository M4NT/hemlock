"""Tests for hemlock.sarif_exporter (v4.7)."""
import json
import pytest
from hemlock.sarif_exporter import (
    hem_report_to_sarif,
    eval_report_to_sarif,
    to_sarif_json,
)
from hemlock.hem_session import HemSession
from hemlock.eval_benchmark import EvalBenchmark


@pytest.fixture()
def hem_report():
    session = HemSession.mock(channels=["rag", "memory"])
    return session.run()


@pytest.fixture()
def eval_report():
    bench = EvalBenchmark.from_mock()
    return bench.run()


def test_hem_report_sarif_schema(hem_report):
    doc = hem_report_to_sarif(hem_report)
    assert doc["version"] == "2.1.0"
    assert "$schema" in doc
    assert "runs" in doc
    assert len(doc["runs"]) == 1


def test_hem_report_sarif_tool(hem_report):
    doc = hem_report_to_sarif(hem_report)
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Hemlock"
    assert "version" in driver
    assert "rules" in driver


def test_hem_report_sarif_results_for_succeeded(hem_report):
    doc = hem_report_to_sarif(hem_report)
    sarif_results = doc["runs"][0]["results"]
    succeeded = [r for r in hem_report.results if r.succeeded]
    assert len(sarif_results) == len(succeeded)


def test_hem_report_sarif_result_fields(hem_report):
    doc = hem_report_to_sarif(hem_report)
    for r in doc["runs"][0]["results"]:
        assert "ruleId" in r
        assert "level" in r
        assert "message" in r
        assert "locations" in r


def test_hem_report_sarif_properties(hem_report):
    doc = hem_report_to_sarif(hem_report)
    props = doc["runs"][0]["properties"]
    assert "target" in props
    assert "riskScore" in props
    assert "channelsAtRisk" in props


def test_hem_report_empty_results():
    from hemlock.hem_session import HemReport
    report = HemReport(target="empty", results=[])
    doc = hem_report_to_sarif(report)
    assert doc["runs"][0]["results"] == []


def test_eval_report_sarif_schema(eval_report):
    doc = eval_report_to_sarif(eval_report)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1


def test_eval_report_sarif_tool(eval_report):
    doc = eval_report_to_sarif(eval_report)
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "Hemlock"


def test_eval_report_sarif_properties(eval_report):
    doc = eval_report_to_sarif(eval_report)
    props = doc["runs"][0]["properties"]
    assert "modelName" in props
    assert "overallScore" in props


def test_to_sarif_json_roundtrip(hem_report):
    doc = hem_report_to_sarif(hem_report)
    s = to_sarif_json(doc)
    parsed = json.loads(s)
    assert parsed["version"] == "2.1.0"


def test_severity_mapping(hem_report):
    doc = hem_report_to_sarif(hem_report)
    for r in doc["runs"][0]["results"]:
        assert r["level"] in ("error", "warning", "note")


def test_rule_ids_no_duplicates(hem_report):
    doc = hem_report_to_sarif(hem_report)
    rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert len(rule_ids) == len(set(rule_ids))
