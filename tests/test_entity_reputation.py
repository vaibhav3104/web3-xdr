"""Tests for entity registry reputation tiers."""
import pytest
from src.enrichment.entity_registry import (
    EntityRegistry, EntityType, ReputationTier, Entity,
    ENTITY_REPUTATION_MAP,
)


class TestReputationTier:
    def setup_method(self):
        self.registry = EntityRegistry()

    def test_cex_is_trusted(self):
        # Binance address
        tier = self.registry.get_reputation_tier("0x28c6c06298d514db089934071355e5743bf21d60")
        assert tier == ReputationTier.TRUSTED

    def test_dex_is_trusted(self):
        # Uniswap V2 Router
        tier = self.registry.get_reputation_tier("0x7a250d5630b4cf539739df2c5dacb4c659f2488d")
        assert tier == ReputationTier.TRUSTED

    def test_bridge_is_trusted(self):
        tier = self.registry.get_reputation_tier("0x98f3c9e6e3face36baad05fe09d375ef1464288b")
        assert tier == ReputationTier.TRUSTED

    def test_protocol_is_trusted(self):
        # Aave V3 Pool
        tier = self.registry.get_reputation_tier("0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2")
        assert tier == ReputationTier.TRUSTED

    def test_smart_money_is_known(self):
        tier = self.registry.get_reputation_tier("0x9b9647431632af44be02ddd22477ed94d14aacaa")
        assert tier == ReputationTier.KNOWN

    def test_unknown_is_neutral(self):
        tier = self.registry.get_reputation_tier("0x0000000000000000000000000000000000000001")
        assert tier == ReputationTier.NEUTRAL

    def test_mixer_is_suspicious(self):
        # Tornado Cash
        tier = self.registry.get_reputation_tier("0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936")
        assert tier == ReputationTier.SUSPICIOUS

    def test_hacker_is_malicious(self):
        # Ronin Bridge Hacker
        tier = self.registry.get_reputation_tier("0x098b716b8aaf21512996dc57eb0615e2383e2f96")
        assert tier == ReputationTier.MALICIOUS

    def test_sanctioned_is_malicious(self):
        tier = self.registry.get_reputation_tier("0x8589427373d6d84e98730d7795d8f6f8731fda16")
        assert tier == ReputationTier.MALICIOUS


class TestShouldSuppressSeverity:
    def setup_method(self):
        self.registry = EntityRegistry()

    def test_trusted_suppresses_low(self):
        # Binance
        assert self.registry.should_suppress_severity(
            "0x28c6c06298d514db089934071355e5743bf21d60", "low"
        ) is True

    def test_trusted_suppresses_medium(self):
        assert self.registry.should_suppress_severity(
            "0x28c6c06298d514db089934071355e5743bf21d60", "medium"
        ) is True

    def test_trusted_suppresses_high(self):
        assert self.registry.should_suppress_severity(
            "0x28c6c06298d514db089934071355e5743bf21d60", "high"
        ) is True

    def test_trusted_does_not_suppress_critical(self):
        assert self.registry.should_suppress_severity(
            "0x28c6c06298d514db089934071355e5743bf21d60", "critical"
        ) is False

    def test_known_suppresses_low(self):
        # Paradigm (smart money)
        assert self.registry.should_suppress_severity(
            "0x9b9647431632af44be02ddd22477ed94d14aacaa", "low"
        ) is True

    def test_known_suppresses_medium(self):
        assert self.registry.should_suppress_severity(
            "0x9b9647431632af44be02ddd22477ed94d14aacaa", "medium"
        ) is True

    def test_known_does_not_suppress_high(self):
        assert self.registry.should_suppress_severity(
            "0x9b9647431632af44be02ddd22477ed94d14aacaa", "high"
        ) is False

    def test_neutral_never_suppresses(self):
        assert self.registry.should_suppress_severity(
            "0x0000000000000000000000000000000000000001", "low"
        ) is False

    def test_malicious_never_suppresses(self):
        assert self.registry.should_suppress_severity(
            "0x098b716b8aaf21512996dc57eb0615e2383e2f96", "low"
        ) is False


class TestEntityRegistryClassification:
    def setup_method(self):
        self.registry = EntityRegistry()

    def test_classify_caches_result(self):
        addr = "0x28c6c06298d514db089934071355e5743bf21d60"
        e1 = self.registry.classify(addr)
        e2 = self.registry.classify(addr)
        assert e1 is e2  # Same object from cache

    def test_add_entity_clears_cache(self):
        addr = "0x0000000000000000000000000000000000000001"
        e1 = self.registry.classify(addr)
        assert e1.entity_type == EntityType.UNKNOWN

        custom = Entity(address=addr, entity_type=EntityType.WHALE, name="Test Whale")
        self.registry.add_entity(custom)
        e2 = self.registry.classify(addr)
        assert e2.entity_type == EntityType.WHALE

    def test_is_trusted(self):
        assert self.registry.is_trusted("0x28c6c06298d514db089934071355e5743bf21d60") is True
        assert self.registry.is_trusted("0x0000000000000000000000000000000000000001") is False

    def test_is_known(self):
        assert self.registry.is_known("0x9b9647431632af44be02ddd22477ed94d14aacaa") is True

    def test_reputation_map_complete(self):
        # Every EntityType should have a mapping
        for et in EntityType:
            assert et in ENTITY_REPUTATION_MAP, f"{et} missing from ENTITY_REPUTATION_MAP"
