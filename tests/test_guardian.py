"""
Guardian System Tests
=====================

Tests for GuardianSystem: protocol registration, action determination,
incident handling (auto-execute vs require-approval), approval flow,
and response history tracking.

All Web3/blockchain calls are mocked so tests run without network access.
"""

import builtins

_real_import = builtins.__import__


def _patched_import(name, *args, **kwargs):
    if name == "torch" or name.startswith("torch."):
        raise ImportError(f"No module named '{name}' (mocked for test)")
    return _real_import(name, *args, **kwargs)


builtins.__import__ = _patched_import

import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, patch
from datetime import datetime, timezone

from src.response.guardian import (
    GuardianSystem,
    ProtocolConfig,
    ResponseAction,
    ResponseStatus,
    ResponseRecord,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def guardian() -> GuardianSystem:
    """Fresh GuardianSystem instance for each test."""
    return GuardianSystem()


@pytest.fixture
def basic_config() -> ProtocolConfig:
    """Protocol config with auto-pause enabled and a guardian key."""
    return ProtocolConfig(
        protocol_name="TestBridge",
        chain_id="ethereum",
        main_contract="0xABCDEF1234567890ABCDEF1234567890ABCDEF12",
        auto_pause_on_critical=True,
        auto_pause_on_high=False,
        require_approval_threshold_usd=1_000_000,
        guardian_private_key="0xdeadbeef",
        emergency_contacts=["@alice", "@bob"],
    )


@pytest.fixture
def multisig_config() -> ProtocolConfig:
    """Protocol config that uses multisig instead of direct pause."""
    return ProtocolConfig(
        protocol_name="MultisigVault",
        chain_id="polygon",
        main_contract="0x1111111111111111111111111111111111111111",
        auto_pause_on_critical=True,
        auto_pause_on_high=False,
        require_approval_threshold_usd=500_000,
        multisig_address="0x9999999999999999999999999999999999999999",
    )


@pytest.fixture
def alertonly_config() -> ProtocolConfig:
    """Protocol config with no guardian key and no multisig -- alert only."""
    return ProtocolConfig(
        protocol_name="AlertPool",
        chain_id="arbitrum",
        main_contract="0x2222222222222222222222222222222222222222",
        auto_pause_on_critical=True,
    )


# ---------------------------------------------------------------------------
# 1. TestProtocolRegistration
# ---------------------------------------------------------------------------


class TestProtocolRegistration:
    def test_register_protocol(self, guardian: GuardianSystem, basic_config: ProtocolConfig):
        guardian.register_protocol("bridge-1", basic_config)
        assert "bridge-1" in guardian.protocols
        assert guardian.protocols["bridge-1"].protocol_name == "TestBridge"

    def test_find_protocol_by_name(self, guardian: GuardianSystem, basic_config: ProtocolConfig):
        guardian.register_protocol("bridge-1", basic_config)
        found = guardian._find_protocol_config("testbridge", "0x0000")
        assert found is not None
        assert found.protocol_name == "TestBridge"

    def test_find_protocol_by_contract(self, guardian: GuardianSystem, basic_config: ProtocolConfig):
        guardian.register_protocol("bridge-1", basic_config)
        found = guardian._find_protocol_config(
            "unknown",
            basic_config.main_contract.lower(),
        )
        assert found is not None

    def test_find_protocol_missing_returns_none(self, guardian: GuardianSystem):
        result = guardian._find_protocol_config("no-such-protocol", "0xdead")
        assert result is None


# ---------------------------------------------------------------------------
# 2. TestActionDetermination
# ---------------------------------------------------------------------------


class TestActionDetermination:
    def test_critical_with_key_pauses(self, guardian: GuardianSystem, basic_config: ProtocolConfig):
        action = guardian._determine_action("critical", basic_config, 100_000)
        assert action == ResponseAction.PAUSE_CONTRACT

    def test_critical_multisig_notifies(self, guardian: GuardianSystem, multisig_config: ProtocolConfig):
        action = guardian._determine_action("critical", multisig_config, 100_000)
        assert action == ResponseAction.NOTIFY_MULTISIG

    def test_critical_no_key_no_multisig_alerts(self, guardian: GuardianSystem, alertonly_config: ProtocolConfig):
        action = guardian._determine_action("critical", alertonly_config, 100_000)
        assert action == ResponseAction.ALERT_ONLY

    def test_low_severity_is_alert_only(self, guardian: GuardianSystem, basic_config: ProtocolConfig):
        action = guardian._determine_action("low", basic_config, 500)
        assert action == ResponseAction.ALERT_ONLY

    def test_high_auto_pause_off_is_alert_only(self, guardian: GuardianSystem, basic_config: ProtocolConfig):
        """High severity with auto_pause_on_high=False defaults to alert."""
        action = guardian._determine_action("high", basic_config, 10_000)
        assert action == ResponseAction.ALERT_ONLY


# ---------------------------------------------------------------------------
# 3. TestHandleIncident
# ---------------------------------------------------------------------------


class TestHandleIncident:
    @pytest.mark.asyncio
    async def test_unknown_protocol_returns_none(self, guardian: GuardianSystem):
        result = await guardian.handle_incident(
            incident_id="inc-001",
            severity="critical",
            attack_type="exploit",
            affected_protocol="unknown_proto",
            estimated_loss_usd=100_000,
            affected_chain="ethereum",
            contract_address="0xdead",
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_alert_only_returns_none(self, guardian: GuardianSystem, alertonly_config: ProtocolConfig):
        """When action resolves to ALERT_ONLY, handle_incident returns None."""
        guardian.register_protocol("alert-pool", alertonly_config)
        result = await guardian.handle_incident(
            incident_id="inc-002",
            severity="critical",
            attack_type="exploit",
            affected_protocol="AlertPool",
            estimated_loss_usd=500,
            affected_chain="arbitrum",
            contract_address=alertonly_config.main_contract,
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_auto_execute_below_threshold(self, guardian: GuardianSystem, basic_config: ProtocolConfig):
        """Loss below threshold -> auto-execute (no approval required)."""
        guardian.register_protocol("bridge-1", basic_config)

        with patch.object(guardian, "_execute_response", new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = lambda rec, cfg: _set_status(rec, ResponseStatus.SUCCESS)

            record = await guardian.handle_incident(
                incident_id="inc-003",
                severity="critical",
                attack_type="exploit",
                affected_protocol="TestBridge",
                estimated_loss_usd=100_000,  # below 1M threshold
                affected_chain="ethereum",
                contract_address=basic_config.main_contract,
            )
            assert record is not None
            mock_exec.assert_awaited_once()
            assert record.status == ResponseStatus.SUCCESS

    @pytest.mark.asyncio
    async def test_requires_approval_above_threshold(self, guardian: GuardianSystem, basic_config: ProtocolConfig):
        """Loss above threshold -> REQUIRES_APPROVAL, added to pending."""
        guardian.register_protocol("bridge-1", basic_config)

        record = await guardian.handle_incident(
            incident_id="inc-004",
            severity="critical",
            attack_type="exploit",
            affected_protocol="TestBridge",
            estimated_loss_usd=5_000_000,  # above 1M threshold
            affected_chain="ethereum",
            contract_address=basic_config.main_contract,
        )
        assert record is not None
        assert record.status == ResponseStatus.REQUIRES_APPROVAL
        assert record.id in guardian.pending_approvals


# ---------------------------------------------------------------------------
# 4. TestApproveResponse
# ---------------------------------------------------------------------------


class TestApproveResponse:
    @pytest.mark.asyncio
    async def test_approve_pending_response(self, guardian: GuardianSystem, basic_config: ProtocolConfig):
        guardian.register_protocol("bridge-1", basic_config)

        # Create a pending record
        record = await guardian.handle_incident(
            incident_id="inc-005",
            severity="critical",
            attack_type="exploit",
            affected_protocol="TestBridge",
            estimated_loss_usd=5_000_000,
            affected_chain="ethereum",
            contract_address=basic_config.main_contract,
        )
        assert record is not None
        resp_id = record.id

        with patch.object(guardian, "_execute_response", new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = lambda rec, cfg: _set_status(rec, ResponseStatus.SUCCESS)

            approved = await guardian.approve_response(resp_id, approved_by="ops-lead")
            assert approved is not None
            assert approved.approved_by == "ops-lead"
            assert approved.status == ResponseStatus.SUCCESS
            assert resp_id not in guardian.pending_approvals

    @pytest.mark.asyncio
    async def test_approve_nonexistent_returns_none(self, guardian: GuardianSystem):
        result = await guardian.approve_response("no-such-id", approved_by="someone")
        assert result is None


# ---------------------------------------------------------------------------
# 5. TestResponseHistory
# ---------------------------------------------------------------------------


class TestResponseHistory:
    @pytest.mark.asyncio
    async def test_history_records_auto_executed(self, guardian: GuardianSystem, basic_config: ProtocolConfig):
        guardian.register_protocol("bridge-1", basic_config)

        with patch.object(guardian, "_execute_response", new_callable=AsyncMock) as mock_exec:
            mock_exec.side_effect = lambda rec, cfg: _set_status(rec, ResponseStatus.SUCCESS)

            await guardian.handle_incident(
                incident_id="inc-h1",
                severity="critical",
                attack_type="exploit",
                affected_protocol="TestBridge",
                estimated_loss_usd=100_000,
                affected_chain="ethereum",
                contract_address=basic_config.main_contract,
            )

        history = guardian.get_response_history()
        assert len(history) == 1
        assert history[0].incident_id == "inc-h1"

    @pytest.mark.asyncio
    async def test_history_records_pending(self, guardian: GuardianSystem, basic_config: ProtocolConfig):
        guardian.register_protocol("bridge-1", basic_config)

        await guardian.handle_incident(
            incident_id="inc-h2",
            severity="critical",
            attack_type="exploit",
            affected_protocol="TestBridge",
            estimated_loss_usd=5_000_000,
            affected_chain="ethereum",
            contract_address=basic_config.main_contract,
        )

        history = guardian.get_response_history()
        assert len(history) == 1
        assert history[0].status == ResponseStatus.REQUIRES_APPROVAL

    def test_get_pending_approvals_list(self, guardian: GuardianSystem):
        """Initially empty; populated after above tests would add entries."""
        assert guardian.get_pending_approvals() == []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _set_status(record: ResponseRecord, status: ResponseStatus) -> ResponseRecord:
    """Helper used as side_effect for mocked _execute_response."""
    record.status = status
    record.completed_at = datetime.now(timezone.utc)
    return record
