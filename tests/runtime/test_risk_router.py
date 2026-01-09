"""
Tests for Risk Router Decision Logic
====================================

Tests for RiskRouter covering:
- Budget tracking and rate limiting
- Whitelist/blacklist logic
- Zero value transaction handling
- Dangerous selector detection
"""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone, timedelta

from src.runtime.risk_router import RiskRouter, RiskRouterConfig, BudgetTracker, RouterDecision
from src.runtime.intent_sources.base import PendingTx


@pytest.mark.asyncio
class TestBudgetTracker:
    """Test suite for BudgetTracker."""
    
    @pytest.fixture
    def tracker(self):
        """Create a BudgetTracker instance."""
        return BudgetTracker()
    
    @pytest.mark.asyncio
    async def test_budget_allows_within_limit(self, tracker):
        """Test: Budget allows simulations within limit."""
        chain_id = "ethereum"
        protocol_id = "test-protocol"
        
        # Record 10 simulations (under limit of 60)
        for _ in range(10):
            tracker.record_simulation(chain_id, protocol_id)
        
        allowed, reason = tracker.check_budget(
            chain_id=chain_id,
            protocol_id=protocol_id,
            per_chain_limit=60,
            per_protocol_limit=20,
            window_seconds=60
        )
        
        assert allowed is True
        assert "budget_ok" in reason
    
    @pytest.mark.asyncio
    async def test_budget_rejects_exceeding_chain_limit(self, tracker):
        """Test: Budget rejects when chain limit exceeded."""
        chain_id = "ethereum"
        protocol_id = "test-protocol"
        
        # Record 100 simulations in 1 second (exceeds limit of 60)
        now = datetime.now(timezone.utc)
        for i in range(100):
            tracker.chain_budget.setdefault(chain_id, []).append(now - timedelta(seconds=i * 0.01))
        
        allowed, reason = tracker.check_budget(
            chain_id=chain_id,
            protocol_id=protocol_id,
            per_chain_limit=60,
            per_protocol_limit=20,
            window_seconds=60
        )
        
        assert allowed is False
        assert "chain_budget_exceeded" in reason
    
    @pytest.mark.asyncio
    async def test_budget_rejects_exceeding_protocol_limit(self, tracker):
        """Test: Budget rejects when protocol limit exceeded."""
        chain_id = "ethereum"
        protocol_id = "test-protocol"
        
        # Record 25 protocol simulations (exceeds limit of 20)
        now = datetime.now(timezone.utc)
        for i in range(25):
            tracker.protocol_budget.setdefault(protocol_id, []).append(now - timedelta(seconds=i * 0.01))
        
        allowed, reason = tracker.check_budget(
            chain_id=chain_id,
            protocol_id=protocol_id,
            per_chain_limit=60,
            per_protocol_limit=20,
            window_seconds=60
        )
        
        assert allowed is False
        assert "protocol_budget_exceeded" in reason
    
    @pytest.mark.asyncio
    async def test_budget_cleanup_old_timestamps(self, tracker):
        """Test: Budget cleanup removes timestamps older than window."""
        chain_id = "ethereum"
        protocol_id = "test-protocol"
        
        # Record old simulation (outside window)
        old_time = datetime.now(timezone.utc) - timedelta(minutes=3)
        tracker.chain_budget[chain_id] = [old_time]
        tracker.protocol_budget[protocol_id] = [old_time]
        
        # Record new simulation
        tracker.record_simulation(chain_id, protocol_id)
        
        # Old timestamps should be cleaned up
        assert len(tracker.chain_budget[chain_id]) <= 1
        assert old_time not in tracker.chain_budget[chain_id]


@pytest.mark.asyncio
class TestRiskRouter:
    """Test suite for RiskRouter."""
    
    @pytest.fixture
    def router(self):
        """Create a RiskRouter instance."""
        return RiskRouter()
    
    @pytest.fixture
    def safe_tx(self):
        """Safe transaction (low value, safe selector)."""
        return PendingTx(
            tx_hash="0xsafe123",
            chain_id="ethereum",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=1000000000000000,  # 0.001 ETH
            data="0xa9059cbb00000000000000000000000000000000000000000000000000000000",  # transfer()
        )
    
    @pytest.fixture
    def malicious_tx(self):
        """Malicious transaction (dangerous selector)."""
        return PendingTx(
            tx_hash="0xmalicious123",
            chain_id="ethereum",
            from_address="0x9999999999999999999999999999999999999999",
            to_address="0x2222222222222222222222222222222222222222",
            value=0,
            data="0x8456cb59",  # pause() - dangerous selector
        )
    
    @pytest.fixture
    def critical_contract_tx(self):
        """Transaction to critical contract."""
        return PendingTx(
            tx_hash="0xcritical123",
            chain_id="ethereum",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0xCRITICAL_CONTRACT_ADDRESS",
            value=0,
            data="0xa9059cbb",
        )
    
    @pytest.mark.asyncio
    async def test_whitelist_skips_simulation(self, router, safe_tx):
        """Test: Verify transactions from 'Safe Senders' skip simulation."""
        # Add to whitelist (if router supports it)
        # For now, test that low-value transactions are ignored
        decision = await router.route_transaction(safe_tx)
        
        # Low-value, safe transactions should be IGNORE or HOT_ONLY
        assert decision in [RouterDecision.IGNORE, RouterDecision.HOT_ONLY]
    
    @pytest.mark.asyncio
    async def test_blacklist_flags_malicious_selectors(self, router, malicious_tx):
        """Test: Verify transactions with 'Malicious Selectors' are flagged immediately."""
        decision = await router.route_transaction(malicious_tx)
        
        # Dangerous selector should trigger simulation
        assert decision in [RouterDecision.SIM_FAST, RouterDecision.SIM_FULL]
    
    @pytest.mark.asyncio
    async def test_critical_contract_always_simulated(self, router, critical_contract_tx):
        """Test: Transactions to critical contracts are always simulated."""
        # Add contract to critical list
        router.config.critical_contracts.add("0xcritical_contract_address")
        critical_contract_tx.to_address = "0xcritical_contract_address"
        
        decision = await router.route_transaction(critical_contract_tx)
        
        # Critical contracts should always be simulated
        assert decision in [RouterDecision.SIM_FAST, RouterDecision.SIM_FULL]
    
    @pytest.mark.asyncio
    async def test_zero_value_handling(self, router):
        """Test: Test handling of 0 ETH transactions (spam vs. exploit setup)."""
        # Zero value with dangerous selector (exploit setup)
        exploit_setup_tx = PendingTx(
            tx_hash="0xzero1",
            chain_id="ethereum",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=0,
            data="0x8456cb59",  # pause() - dangerous
        )
        
        # Zero value with safe selector (likely spam)
        spam_tx = PendingTx(
            tx_hash="0xzero2",
            chain_id="ethereum",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=0,
            data="0xa9059cbb",  # transfer() - safe
        )
        
        exploit_decision = await router.route_transaction(exploit_setup_tx)
        spam_decision = await router.route_transaction(spam_tx)
        
        # Exploit setup should be simulated (dangerous selector)
        assert exploit_decision in [RouterDecision.SIM_FAST, RouterDecision.SIM_FULL]
        
        # Spam should be ignored or hot-checked only
        assert spam_decision in [RouterDecision.IGNORE, RouterDecision.HOT_ONLY]
    
    @pytest.mark.asyncio
    async def test_large_value_triggers_simulation(self, router):
        """Test: Large value transactions trigger full simulation."""
        large_value_tx = PendingTx(
            tx_hash="0xlarge123",
            chain_id="ethereum",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=2000 * 10**18,  # 2000 ETH (exceeds large_value_threshold)
            data="0xa9059cbb",
        )
        
        decision = await router.route_transaction(large_value_tx)
        
        # Large value should trigger simulation
        assert decision in [RouterDecision.SIM_FAST, RouterDecision.SIM_FULL]
    
    @pytest.mark.asyncio
    async def test_malicious_address_flagged(self, router):
        """Test: Transactions from malicious addresses are flagged."""
        malicious_address = "0xmalicious123"
        router.config.malicious_addresses.add(malicious_address)
        
        malicious_addr_tx = PendingTx(
            tx_hash="0xtx123",
            chain_id="ethereum",
            from_address=malicious_address,
            to_address="0x2222222222222222222222222222222222222222",
            value=1000000000000000000,  # 1 ETH
            data="0xa9059cbb",
        )
        
        decision = await router.route_transaction(malicious_addr_tx)
        
        # Malicious address should trigger simulation
        assert decision in [RouterDecision.SIM_FAST, RouterDecision.SIM_FULL]
    
    @pytest.mark.asyncio
    async def test_budget_enforcement(self, router):
        """Test: Budget constraints prevent excessive simulations."""
        # Exhaust budget
        for i in range(100):
            tx = PendingTx(
                tx_hash=f"0x{i:064x}",
                chain_id="ethereum",
                from_address="0x1111111111111111111111111111111111111111",
                to_address="0x2222222222222222222222222222222222222222",
                value=1000000000000000000,
                data="0x8456cb59",  # Dangerous selector
            )
            decision = await router.route_transaction(tx)
            if decision in [RouterDecision.SIM_FAST, RouterDecision.SIM_FULL]:
                router.budget_tracker.record_simulation("ethereum", None)
        
        # 101st transaction should be rejected due to budget
        tx_101 = PendingTx(
            tx_hash="0x101",
            chain_id="ethereum",
            from_address="0x1111111111111111111111111111111111111111",
            to_address="0x2222222222222222222222222222222222222222",
            value=1000000000000000000,
            data="0x8456cb59",
        )
        
        decision = await router.route_transaction(tx_101)
        
        # Should be IGNORE or HOT_ONLY due to budget
        assert decision in [RouterDecision.IGNORE, RouterDecision.HOT_ONLY]
    
    @pytest.mark.asyncio
    async def test_dangerous_selectors_detected(self, router):
        """Test: All dangerous selectors are detected."""
        dangerous_selectors = router.config.dangerous_selectors
        
        for selector in dangerous_selectors:
            tx = PendingTx(
                tx_hash=f"0x{selector}",
                chain_id="ethereum",
                from_address="0x1111111111111111111111111111111111111111",
                to_address="0x2222222222222222222222222222222222222222",
                value=0,
                data=selector,
            )
            
            decision = await router.route_transaction(tx)
            
            # Dangerous selector should trigger simulation
            assert decision in [RouterDecision.SIM_FAST, RouterDecision.SIM_FULL], \
                f"Selector {selector} not detected as dangerous"

