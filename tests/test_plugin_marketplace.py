"""Tests for hemlock.plugin_marketplace (v5.5)."""
import pytest
from hemlock.plugin_marketplace import PluginMarketplace, MarketplaceEntry


@pytest.fixture()
def market():
    return PluginMarketplace(mock=True)


def test_all_returns_entries(market):
    entries = market.all()
    assert len(entries) > 0
    assert all(isinstance(e, MarketplaceEntry) for e in entries)


def test_featured_subset(market):
    featured = market.featured()
    assert len(featured) > 0
    assert all(e.featured for e in featured)


def test_search_by_name(market):
    results = market.search("firewall")
    assert any("firewall" in e.name for e in results)


def test_search_by_tag(market):
    results = market.search("backdoor")
    assert len(results) > 0


def test_search_no_results(market):
    results = market.search("xxxxxx_not_found_xxxxx")
    assert results == []


def test_filter_type_attack(market):
    attacks = market.filter_type("attack")
    assert all(e.package_type in ("attack", "both") for e in attacks)


def test_filter_type_defense(market):
    defenses = market.filter_type("defense")
    assert all(e.package_type in ("defense", "both") for e in defenses)


def test_verified_only(market):
    verified = market.verified_only()
    assert all(e.verified for e in verified)


def test_top_rated(market):
    top = market.top_rated(2)
    assert len(top) == 2
    assert top[0].rating >= top[1].rating


def test_get_existing(market):
    entry = market.get("hemlock-plugin-semantic-backdoor")
    assert entry is not None
    assert entry.name == "hemlock-plugin-semantic-backdoor"


def test_get_missing(market):
    entry = market.get("nonexistent-package-xyz")
    assert entry is None


def test_entry_to_dict(market):
    entry = market.all()[0]
    d = entry.to_dict()
    assert "name" in d
    assert "version" in d
    assert "verified" in d


def test_verify_manifest_verified_entry(market):
    verified = market.verified_only()
    assert len(verified) > 0
    assert market.verify_manifest(verified[0])


def test_verify_manifest_unverified_entry(market):
    all_entries = market.all()
    unverified = [e for e in all_entries if not e.verified]
    if unverified:
        assert not market.verify_manifest(unverified[0])


def test_install_verified_raises_for_unverified(market):
    unverified = [e for e in market.all() if not e.verified]
    if unverified:
        with pytest.raises(ValueError, match="not verified"):
            market.install_verified(unverified[0].name)
