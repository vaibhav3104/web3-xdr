"""
Database Service Tests for Sentinel3
======================================

Tests DatabaseService methods with mocked database sessions.
No real database required - all SQLAlchemy async sessions are mocked.
"""

import builtins

_real_import = builtins.__import__
def _patched_import(name, *args, **kwargs):
    if name == "torch" or name.startswith("torch."):
        raise ImportError(f"No module named '{name}' (mocked for test)")
    return _real_import(name, *args, **kwargs)

# Temporarily patch import to block torch, then restore immediately after loading src
builtins.__import__ = _patched_import
try:
    from src.database.service import DatabaseService
    from src.database.models import EventModel, IncidentModel, SimulationRunModel
finally:
    builtins.__import__ = _real_import

import pytest
import uuid
import json
import base64
from unittest.mock import patch, AsyncMock, MagicMock, PropertyMock
from datetime import datetime, timezone, timedelta
from contextlib import asynccontextmanager
from decimal import Decimal


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_async_session():
    """Create a mock async session with standard methods."""
    session = AsyncMock()
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.execute = AsyncMock()
    session.begin_nested = AsyncMock()
    return session


@asynccontextmanager
async def _mock_get_session(session):
    """Async context manager that yields the given mock session."""
    yield session


def _encode_cursor(timestamp, event_id):
    """Encode a cursor for testing pagination."""
    data = {"timestamp": timestamp.isoformat(), "id": str(event_id)}
    return base64.b64encode(json.dumps(data).encode()).decode()


def _make_event_data(**overrides):
    """Build sample event data dict."""
    base = {
        "event_id": f"evt_{uuid.uuid4().hex[:12]}",
        "chain_id": "ethereum",
        "event_type": "transfer",
        "tx_hash": f"0x{'ab' * 32}",
        "block_number": 18000000,
        "block_timestamp": datetime.now(timezone.utc),
        "log_index": 0,
        "contract_address": f"0x{'cc' * 20}",
        "from_address": f"0x{'11' * 20}",
        "to_address": f"0x{'22' * 20}",
        "amount": 1.5,
        "amount_usd": 3000.0,
        "asset_type": "ERC20",
        "asset_address": f"0x{'dd' * 20}",
        "severity": "MEDIUM",
        "raw_data": {"foo": "bar"},
        "topics": ["0xddf252ad"],
    }
    base.update(overrides)
    return base


def _make_incident_data(**overrides):
    """Build sample incident data dict."""
    base = {
        "incident_id": f"inc_{uuid.uuid4().hex[:12]}",
        "cluster_key": f"cluster_{uuid.uuid4().hex[:8]}",
        "title": "Flash Loan Attack Detected",
        "summary": "Large flash loan followed by price manipulation",
        "severity": "CRITICAL",
        "status": "OPEN_PENDING",
        "attack_type": "FLASH_LOAN",
        "confidence": 0.9,
        "total_loss_usd": 50000,
        "affected_chains": ["ethereum"],
        "affected_contracts": [f"0x{'cc' * 20}"],
        "affected_addresses": [f"0x{'11' * 20}"],
        "event_ids": ["evt_001", "evt_002"],
        "violation_ids": [],
        "rule_ids": ["rule_flash_loan"],
        "recommended_actions": ["Pause contract"],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# TestSaveEvent
# ---------------------------------------------------------------------------

class TestSaveEvent:
    """Tests for DatabaseService.save_event."""

    @pytest.mark.asyncio
    async def test_save_event_success(self):
        """save_event should add an EventModel to the session and return event_id."""
        session = _make_async_session()
        event_data = _make_event_data()

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            result = await DatabaseService.save_event(event_data)

        # session.add should have been called with an EventModel instance
        session.add.assert_called_once()
        added_obj = session.add.call_args[0][0]
        assert isinstance(added_obj, EventModel)
        assert added_obj.event_id == event_data["event_id"]
        assert added_obj.chain_id == "ethereum"
        assert added_obj.severity == "MEDIUM"

        # flush is called to persist within the transaction
        session.flush.assert_awaited_once()

        # Should return the event_id
        assert result == event_data["event_id"]

    @pytest.mark.asyncio
    async def test_save_event_default_severity(self):
        """save_event should default severity to LOW when not provided."""
        session = _make_async_session()
        event_data = _make_event_data()
        del event_data["severity"]

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            await DatabaseService.save_event(event_data)

        added_obj = session.add.call_args[0][0]
        assert added_obj.severity == "LOW"

    @pytest.mark.asyncio
    async def test_save_event_propagates_exception(self):
        """save_event should propagate database exceptions."""
        session = _make_async_session()
        session.flush.side_effect = Exception("unique constraint violated")
        event_data = _make_event_data()

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            with pytest.raises(Exception, match="unique constraint violated"):
                await DatabaseService.save_event(event_data)


# ---------------------------------------------------------------------------
# TestSaveEventsBatch
# ---------------------------------------------------------------------------

class TestSaveEventsBatch:
    """Tests for DatabaseService.save_events_batch."""

    @pytest.mark.asyncio
    async def test_batch_save_empty_list(self):
        """Passing empty list should return 0 without touching the database."""
        result = await DatabaseService.save_events_batch([])
        assert result == 0

    @pytest.mark.asyncio
    async def test_batch_save_executes_sql(self):
        """Batch save should execute raw SQL INSERT for each event."""
        session = _make_async_session()
        # begin_nested returns an async context for savepoints
        mock_savepoint = AsyncMock()
        mock_savepoint.commit = AsyncMock()
        mock_savepoint.rollback = AsyncMock()
        session.begin_nested = AsyncMock(return_value=mock_savepoint)

        events = [_make_event_data(event_id=f"evt_{i}") for i in range(3)]

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            result = await DatabaseService.save_events_batch(events)

        # Should execute INSERT for each event
        assert session.execute.await_count == 3
        # Savepoint commit called for each
        assert mock_savepoint.commit.await_count == 3
        # Overall commit
        session.commit.assert_awaited_once()
        assert result == 3

    @pytest.mark.asyncio
    async def test_batch_save_skips_events_without_id(self):
        """Events missing event_id should be skipped."""
        session = _make_async_session()
        mock_savepoint = AsyncMock()
        mock_savepoint.commit = AsyncMock()
        mock_savepoint.rollback = AsyncMock()
        session.begin_nested = AsyncMock(return_value=mock_savepoint)

        bad_event = _make_event_data()
        del bad_event["event_id"]  # Remove key entirely so .get() returns None
        events = [
            _make_event_data(event_id="evt_good"),
            bad_event,
            _make_event_data(event_id="evt_also_good"),
        ]

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            result = await DatabaseService.save_events_batch(events)

        # Only 2 should be inserted (the one with None id is skipped)
        assert session.execute.await_count == 2
        assert result == 2

    @pytest.mark.asyncio
    async def test_batch_save_individual_failure_continues(self):
        """A failure on one event should not block other events."""
        session = _make_async_session()
        mock_savepoint = AsyncMock()
        mock_savepoint.commit = AsyncMock()
        mock_savepoint.rollback = AsyncMock()
        session.begin_nested = AsyncMock(return_value=mock_savepoint)

        call_count = 0
        async def _execute_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise Exception("duplicate key")
        session.execute = AsyncMock(side_effect=_execute_side_effect)

        events = [_make_event_data(event_id=f"evt_{i}") for i in range(3)]

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            result = await DatabaseService.save_events_batch(events)

        # 2 out of 3 should succeed (second fails and is rolled back)
        assert result == 2
        # Savepoint rollback called once for the failed event
        assert mock_savepoint.rollback.await_count == 1


# ---------------------------------------------------------------------------
# TestGetEvents
# ---------------------------------------------------------------------------

class TestGetEvents:
    """Tests for DatabaseService.get_events."""

    @pytest.mark.asyncio
    async def test_get_events_no_filters(self):
        """get_events with no filters should return all events."""
        session = _make_async_session()
        # Mock fetchall to return empty result
        mock_result = MagicMock()
        mock_result.fetchall.return_value = []
        session.execute = AsyncMock(return_value=mock_result)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            events, next_cursor = await DatabaseService.get_events()

        assert events == []
        assert next_cursor is None
        session.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_events_with_chain_filter(self):
        """get_events should filter by chain_id when provided."""
        session = _make_async_session()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = []
        session.execute = AsyncMock(return_value=mock_result)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            events, _ = await DatabaseService.get_events(chain_id="ethereum")

        # Verify the SQL was executed with chain_id param
        call_args = session.execute.call_args
        params = call_args[0][1]
        assert params["chain_id"] == "ethereum"

    @pytest.mark.asyncio
    async def test_get_events_with_severity_filter(self):
        """get_events should filter by severity (uppercased)."""
        session = _make_async_session()
        mock_result = MagicMock()
        mock_result.fetchall.return_value = []
        session.execute = AsyncMock(return_value=mock_result)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            events, _ = await DatabaseService.get_events(severity="critical")

        params = session.execute.call_args[0][1]
        assert params["severity"] == "CRITICAL"

    @pytest.mark.asyncio
    async def test_get_events_returns_dicts(self):
        """get_events should convert raw rows to dicts."""
        session = _make_async_session()
        test_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        # Row tuple matching SELECT columns:
        # id, event_id, chain_id, event_type, tx_hash, block_number,
        # block_timestamp, contract_address, severity, amount, amount_usd,
        # from_address, to_address, raw_data, created_at
        mock_row = (
            test_id, "evt_123", "ethereum", "transfer", "0xabc", 18000000,
            now, "0xcontract", "HIGH", Decimal("1.5"), Decimal("3000"),
            "0xfrom", "0xto", {"key": "val"}, now,
        )
        mock_result = MagicMock()
        mock_result.fetchall.return_value = [mock_row]
        session.execute = AsyncMock(return_value=mock_result)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            events, _ = await DatabaseService.get_events(limit=10)

        assert len(events) == 1
        evt = events[0]
        assert evt["event_id"] == "evt_123"
        assert evt["chain_id"] == "ethereum"
        assert evt["severity"] == "HIGH"
        assert evt["amount"] == 1.5
        assert evt["raw_data"] == {"key": "val"}

    @pytest.mark.asyncio
    async def test_get_events_cursor_pagination(self):
        """When more results than limit, next_cursor should be returned."""
        session = _make_async_session()
        now = datetime.now(timezone.utc)

        # Return limit+1 rows to trigger cursor generation
        rows = []
        for i in range(4):  # limit=3, so 4 rows triggers next_cursor
            rows.append((
                uuid.uuid4(), f"evt_{i}", "ethereum", "transfer", f"0x{i}",
                18000000 + i, now - timedelta(minutes=i), "0xcontract",
                "LOW", None, None, None, None, {}, now - timedelta(minutes=i),
            ))

        mock_result = MagicMock()
        mock_result.fetchall.return_value = rows
        session.execute = AsyncMock(return_value=mock_result)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            events, next_cursor = await DatabaseService.get_events(limit=3)

        # Should return exactly 3 events (trimmed from 4)
        assert len(events) == 3
        # Cursor should be present
        assert next_cursor is not None
        # Cursor should be decodable
        decoded = json.loads(base64.b64decode(next_cursor))
        assert "timestamp" in decoded
        assert "id" in decoded


# ---------------------------------------------------------------------------
# TestGetIncidents
# ---------------------------------------------------------------------------

class TestGetIncidents:
    """Tests for DatabaseService.get_incidents."""

    @pytest.mark.asyncio
    async def test_get_incidents_empty(self):
        """get_incidents should return empty list when no incidents."""
        session = _make_async_session()
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        session.execute = AsyncMock(return_value=mock_result)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            incidents = await DatabaseService.get_incidents()

        assert incidents == []

    @pytest.mark.asyncio
    async def test_get_incidents_returns_formatted_dicts(self):
        """get_incidents should format IncidentModel objects into dicts."""
        session = _make_async_session()

        # Create a mock IncidentModel
        mock_incident = MagicMock(spec=IncidentModel)
        mock_incident.incident_id = "inc_001"
        mock_incident.title = "Flash Loan Attack"
        mock_incident.severity = "CRITICAL"
        mock_incident.status = "OPEN_PENDING"
        mock_incident.attack_type = "FLASH_LOAN"
        mock_incident.confidence = 0.95
        mock_incident.total_loss_usd = Decimal("50000.00")
        mock_incident.affected_chains = ["ethereum"]
        mock_incident.created_at = datetime(2024, 1, 15, tzinfo=timezone.utc)
        mock_incident.event_count = 5
        mock_incident.affected_contracts = ["0xcontract"]
        mock_incident.affected_addresses = ["0xattacker"]
        mock_incident.summary = "Test summary"
        mock_incident.recommended_actions = ["Pause"]
        mock_incident.rule_ids = ["rule_01"]
        mock_incident.cluster_key = "cluster_abc"

        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = [mock_incident]
        mock_result.scalars.return_value = mock_scalars
        session.execute = AsyncMock(return_value=mock_result)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            incidents = await DatabaseService.get_incidents()

        assert len(incidents) == 1
        inc = incidents[0]
        assert inc["id"] == "inc_001"
        assert inc["severity"] == "critical"  # lowercased in output
        assert inc["status"] == "open_pending"  # lowercased in output
        assert inc["attack_type"] == "FLASH_LOAN"
        assert inc["confidence"] == 0.95
        assert inc["event_count"] == 5

    @pytest.mark.asyncio
    async def test_get_incidents_severity_filter(self):
        """get_incidents should apply severity filter."""
        session = _make_async_session()
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        session.execute = AsyncMock(return_value=mock_result)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            # Should not raise; filter is applied via ORM where clause
            incidents = await DatabaseService.get_incidents(severity="HIGH")

        assert incidents == []
        session.execute.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_incidents_error_returns_empty(self):
        """get_incidents should return empty list on database error."""
        session = _make_async_session()
        session.execute = AsyncMock(side_effect=Exception("connection refused"))

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            incidents = await DatabaseService.get_incidents()

        assert incidents == []


# ---------------------------------------------------------------------------
# TestGetIncident
# ---------------------------------------------------------------------------

class TestGetIncident:
    """Tests for DatabaseService.get_incident (single incident)."""

    @pytest.mark.asyncio
    async def test_get_incident_found(self):
        """get_incident should return the IncidentModel when found."""
        session = _make_async_session()
        mock_incident = MagicMock(spec=IncidentModel)
        mock_incident.incident_id = "inc_001"

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_incident
        session.execute = AsyncMock(return_value=mock_result)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            result = await DatabaseService.get_incident("inc_001")

        assert result is not None
        assert result.incident_id == "inc_001"

    @pytest.mark.asyncio
    async def test_get_incident_not_found(self):
        """get_incident should return None when incident does not exist."""
        session = _make_async_session()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=mock_result)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            result = await DatabaseService.get_incident("nonexistent")

        assert result is None


# ---------------------------------------------------------------------------
# TestGetIncidentStats (equivalent to get_stats)
# ---------------------------------------------------------------------------

class TestGetIncidentStats:
    """Tests for DatabaseService.get_incident_stats."""

    @pytest.mark.asyncio
    async def test_get_incident_stats_aggregation(self):
        """get_incident_stats should aggregate total, by_severity, and active counts."""
        session = _make_async_session()

        call_count = 0
        async def _execute_side_effect(query, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_result = MagicMock()
            if call_count == 1:
                # Total count
                mock_result.scalar.return_value = 42
            elif call_count == 2:
                # By severity - return iterable of rows
                row_critical = MagicMock()
                row_critical.severity = "CRITICAL"
                row_critical.count = 10
                row_high = MagicMock()
                row_high.severity = "HIGH"
                row_high.count = 32
                mock_result.__iter__ = MagicMock(return_value=iter([row_critical, row_high]))
            elif call_count == 3:
                # Active count
                mock_result.scalar.return_value = 15
            return mock_result

        session.execute = AsyncMock(side_effect=_execute_side_effect)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            stats = await DatabaseService.get_incident_stats()

        assert stats["total"] == 42
        assert stats["by_severity"]["CRITICAL"] == 10
        assert stats["by_severity"]["HIGH"] == 32
        assert stats["active"] == 15

    @pytest.mark.asyncio
    async def test_get_incident_stats_empty_db(self):
        """get_incident_stats should handle zero counts gracefully."""
        session = _make_async_session()

        call_count = 0
        async def _execute_side_effect(query, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            mock_result = MagicMock()
            if call_count == 1:
                mock_result.scalar.return_value = 0
            elif call_count == 2:
                mock_result.__iter__ = MagicMock(return_value=iter([]))
            elif call_count == 3:
                mock_result.scalar.return_value = 0
            return mock_result

        session.execute = AsyncMock(side_effect=_execute_side_effect)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            stats = await DatabaseService.get_incident_stats()

        assert stats["total"] == 0
        assert stats["by_severity"] == {}
        assert stats["active"] == 0


# ---------------------------------------------------------------------------
# TestGetSimulationByTx
# ---------------------------------------------------------------------------

class TestGetSimulationByTx:
    """Tests for DatabaseService.get_simulation_by_tx."""

    @pytest.mark.asyncio
    async def test_simulation_found(self):
        """get_simulation_by_tx should return dict when simulation exists."""
        session = _make_async_session()
        sim_id = uuid.uuid4()
        now = datetime.now(timezone.utc)

        mock_sim = MagicMock(spec=SimulationRunModel)
        mock_sim.id = sim_id
        mock_sim.chain_id = "ethereum"
        mock_sim.tx_hash = "0xdeadbeef"
        mock_sim.mode = "FAST"
        mock_sim.status = "SUCCESS"
        mock_sim.duration_ms = 150
        mock_sim.confidence = 0.85
        mock_sim.invariant_results = {"checks": []}
        mock_sim.created_at = now

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_sim
        session.execute = AsyncMock(return_value=mock_result)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            result = await DatabaseService.get_simulation_by_tx("0xdeadbeef")

        assert result is not None
        assert result["tx_hash"] == "0xdeadbeef"
        assert result["chain_id"] == "ethereum"
        assert result["mode"] == "FAST"
        assert result["status"] == "SUCCESS"
        assert result["confidence"] == 0.85
        assert result["duration_ms"] == 150

    @pytest.mark.asyncio
    async def test_simulation_not_found(self):
        """get_simulation_by_tx should return None when no simulation exists."""
        session = _make_async_session()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=mock_result)

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            result = await DatabaseService.get_simulation_by_tx("0xnonexistent")

        assert result is None

    @pytest.mark.asyncio
    async def test_simulation_db_error_returns_none(self):
        """get_simulation_by_tx should return None on database error."""
        session = _make_async_session()
        session.execute = AsyncMock(side_effect=Exception("connection lost"))

        with patch(
            "src.database.service.DatabaseManager.get_session",
            return_value=_mock_get_session(session),
        ):
            result = await DatabaseService.get_simulation_by_tx("0xbad")

        assert result is None
