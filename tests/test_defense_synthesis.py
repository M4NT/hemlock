"""Tests for DefenseSynthesizer (v3.8) — HemReport built from hand-made results."""

from __future__ import annotations

from defenses import OutputDefense, OutputDefenseChain
from hemlock.defense_synthesis import DefenseSynthesizer, SynthesisResult
from hemlock.hem_session import ChannelResult, HemReport


def _report(channels_with_severity):
    results = [
        ChannelResult(channel=ch, variant="v", succeeded=True, severity=sev, detail="d")
        for ch, sev in channels_with_severity
    ]
    return HemReport(target="t", results=results)


def test_synthesize_maps_at_risk_channels():
    report = _report([("rag", "high"), ("cross_agent", "critical")])
    synth = DefenseSynthesizer(report)
    results = synth.synthesize()
    channels = {r.channel for r in results}
    assert channels == {"rag", "cross_agent"}
    assert all(isinstance(r, SynthesisResult) for r in results)


def test_low_severity_channels_ignored():
    report = _report([("rag", "low"), ("tool_output", "none")])
    synth = DefenseSynthesizer(report)
    assert synth.synthesize() == []


def test_rag_defense_names():
    report = _report([("rag", "high")])
    result = DefenseSynthesizer(report).synthesize()[0]
    assert result.defenses == ["InjectionSuccessGuard", "ExfiltrationGuard"]
    assert result.reasoning


def test_defense_objects_instantiated():
    report = _report([("tool_output", "high")])
    result = DefenseSynthesizer(report).synthesize()[0]
    assert result.defense_objects
    assert all(hasattr(o, "validate") or hasattr(o, "validate_write")
               for o in result.defense_objects)


def test_build_chain_returns_output_chain():
    report = _report([("rag", "high")])
    chain = DefenseSynthesizer(report).build_chain("rag")
    assert isinstance(chain, OutputDefenseChain)
    assert len(chain) == 2
    assert all(isinstance(d, OutputDefense) for d in chain.defenses)


def test_build_chain_excludes_ingest_only_defense():
    # memory maps to MemoryBoundaryGuard which is an IngestDefense, not OutputDefense
    report = _report([("memory", "critical")])
    chain = DefenseSynthesizer(report).build_chain("memory")
    assert isinstance(chain, OutputDefenseChain)
    assert len(chain) == 0


def test_build_chain_unknown_channel_empty():
    report = _report([("rag", "high")])
    chain = DefenseSynthesizer(report).build_chain("nonexistent")
    assert len(chain) == 0


def test_chain_validate_flags_injection():
    report = _report([("rag", "high")])
    chain = DefenseSynthesizer(report).build_chain("rag")
    rep = chain.validate("Done. [PWNED]")
    assert rep.triggered is True


def test_chain_validate_clean_response():
    report = _report([("rag", "high")])
    chain = DefenseSynthesizer(report).build_chain("rag")
    rep = chain.validate("The privacy policy was updated in January.")
    assert rep.triggered is False


def test_summary_markdown():
    report = _report([("rag", "high"), ("graph", "critical")])
    md = DefenseSynthesizer(report).summary()
    assert "Defense Synthesis" in md
    assert "rag" in md and "graph" in md


def test_summary_no_risk():
    report = _report([("rag", "low")])
    md = DefenseSynthesizer(report).summary()
    assert "No at-risk channels" in md
