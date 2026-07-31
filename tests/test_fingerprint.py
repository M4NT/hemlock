"""Tests for hemlock.fingerprint (v6.1)."""

import pytest
from hemlock.fingerprint import (
    FingerprintVector,
    FingerprintDiff,
    PipelineFingerprint,
)


def make_vector(scores=None, model_version="v1"):
    scores = scores or {"injection": 80, "exfiltration": 90}
    return FingerprintVector(scores=scores, model_version=model_version)


def test_fingerprint_vector_hash_computed():
    v = make_vector()
    assert v.hash
    assert len(v.hash) == 12


def test_fingerprint_vector_hash_stable():
    v1 = make_vector(scores={"a": 80}, model_version="test")
    v2 = make_vector(scores={"a": 80}, model_version="test")
    assert v1.hash == v2.hash


def test_fingerprint_vector_hash_differs_on_scores():
    v1 = make_vector(scores={"a": 80})
    v2 = make_vector(scores={"a": 70})
    assert v1.hash != v2.hash


def test_fingerprint_vector_to_dict():
    v = make_vector()
    d = v.to_dict()
    assert d["model_version"] == "v1"
    assert "scores" in d
    assert "hash" in d


def test_fingerprint_vector_to_json():
    import json
    v = make_vector()
    doc = json.loads(v.to_json())
    assert "scores" in doc


def test_fingerprint_diff_no_drift():
    v1 = make_vector(scores={"injection": 80, "exfiltration": 90})
    v2 = make_vector(scores={"injection": 82, "exfiltration": 91})  # delta ≤5
    diff = v2.diff(v1, drift_threshold=5)
    assert not diff.drifted_categories
    assert not diff.is_regression


def test_fingerprint_diff_detects_drift():
    baseline = make_vector(scores={"injection": 80})
    current = make_vector(scores={"injection": 60})  # delta = -20 > 5
    diff = current.diff(baseline, drift_threshold=5)
    assert "injection" in diff.drifted_categories


def test_fingerprint_diff_regression_when_scores_drop():
    baseline = make_vector(scores={"injection": 80})
    current = make_vector(scores={"injection": 60})
    diff = current.diff(baseline)
    assert diff.is_regression
    assert "injection" in diff.regression_categories


def test_fingerprint_diff_no_regression_when_scores_improve():
    baseline = make_vector(scores={"injection": 60})
    current = make_vector(scores={"injection": 80})
    diff = current.diff(baseline)
    assert not diff.is_regression
    assert diff.drifted_categories  # drifted but improved


def test_fingerprint_diff_summary_no_drift():
    v = make_vector()
    diff = v.diff(v)
    assert "No behavioral drift" in diff.summary()


def test_fingerprint_diff_summary_with_regression():
    baseline = make_vector(scores={"injection": 90})
    current = make_vector(scores={"injection": 50})
    diff = current.diff(baseline)
    summary = diff.summary()
    assert "REGRESSION" in summary
    assert "injection" in summary


def test_fingerprint_diff_to_dict():
    baseline = make_vector(scores={"injection": 80})
    current = make_vector(scores={"injection": 60})
    diff = current.diff(baseline)
    d = diff.to_dict()
    assert "deltas" in d
    assert "is_regression" in d


def test_pipeline_fingerprint_from_mock():
    fp = PipelineFingerprint.from_mock(model_version="test-model")
    assert fp.model_version == "test-model"


def test_pipeline_fingerprint_compute():
    fp = PipelineFingerprint.from_mock(model_version="test")
    vector = fp.compute()
    assert isinstance(vector, FingerprintVector)
    assert vector.scores
    assert vector.model_version == "test"


def test_pipeline_fingerprint_compute_hash():
    fp = PipelineFingerprint.from_mock(model_version="x")
    v = fp.compute()
    assert len(v.hash) == 12


def test_pipeline_fingerprint_categories_filter():
    fp = PipelineFingerprint.from_mock(
        model_version="y",
        categories=["injection"],
    )
    vector = fp.compute()
    assert isinstance(vector, FingerprintVector)
