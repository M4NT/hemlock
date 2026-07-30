"""Tests for the auto-discovery attack registry."""


from attacks.base import Attack
from attacks.registry import ATTACK_REGISTRY, discover_attacks


class TestDiscoverAttacks:
    def test_returns_dict(self):
        registry = discover_attacks()
        assert isinstance(registry, dict)

    def test_discovers_all_known_attacks(self):
        expected = {
            "direct_injection",
            "context_override",
            "poisoning",
            "indirect_injection",
            "exfiltration",
            "jailbreak_via_context",
            "authority_spoofing",
            "chain_of_thought_hijack",
            "citation_forgery",
            "context_flooding",
            "invisible_markup",
            "temporal_spoofing",
            "semantic_backdoor",
            "multi_hop_poisoning",
            "cross_tenant_poisoning",
        }
        registry = discover_attacks()
        assert expected.issubset(set(registry.keys()))

    def test_excludes_base_and_fuzzer(self):
        registry = discover_attacks()
        assert "base" not in registry
        assert "fuzzer" not in registry
        assert "registry" not in registry

    def test_all_values_are_attack_subclasses(self):
        registry = discover_attacks()
        for name, cls in registry.items():
            assert issubclass(cls, Attack), f"{name} is not an Attack subclass"

    def test_all_classes_are_not_abstract(self):
        registry = discover_attacks()
        for name, cls in registry.items():
            # Should be instantiable (not abstract) — test by checking for run/setup methods
            assert hasattr(cls, "run"), f"{name}.run missing"
            assert hasattr(cls, "setup"), f"{name}.setup missing"
            assert hasattr(cls, "_score"), f"{name}._score missing"

    def test_all_have_name_attribute(self):
        registry = discover_attacks()
        for name, cls in registry.items():
            assert cls.name, f"{name}.name is empty"

    def test_all_have_reference_attribute(self):
        registry = discover_attacks()
        for name, cls in registry.items():
            assert cls.reference, f"{name}.reference is empty"

    def test_module_level_registry_is_populated(self):
        assert len(ATTACK_REGISTRY) >= 15

    def test_module_level_registry_matches_discover(self):
        fresh = discover_attacks()
        # Both should have the same keys
        assert set(ATTACK_REGISTRY.keys()) == set(fresh.keys())

    def test_registry_keys_match_module_filenames(self):
        registry = discover_attacks()
        # Keys should be snake_case without .py
        for key in registry:
            assert key.replace("_", "").isalpha() or "_" in key
            assert not key.endswith(".py")
            assert not key.startswith("_")

    def test_instantiation_with_pipeline(self, pipeline):
        registry = discover_attacks()
        for name, cls in registry.items():
            # Should construct without error (default variant)
            instance = cls(pipeline)
            assert instance is not None


class TestAttackRegistryInit:
    def test_init_exports_attack_registry(self):
        from attacks import ATTACK_REGISTRY
        assert len(ATTACK_REGISTRY) >= 15

    def test_init_exports_discover_attacks(self):
        from attacks import discover_attacks
        assert callable(discover_attacks)

    def test_init_exports_base_classes(self):
        from attacks import Attack, AttackResult
        assert Attack is not None
        assert AttackResult is not None
