"""
Core Module Tests
=================

Tests for critical modules that previously had zero test coverage:
- src/database/connection.py  (DatabaseManager)
- src/database/service.py     (DatabaseService)
- src/pipeline/bus.py         (EventBus / InMemoryBus)
- src/response/telegram.py    (TelegramAlerter)
- src/metrics/collector.py    (XDRMetrics / helper functions)
"""

import asyncio
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest
from prometheus_client import CollectorRegistry


# ============================================================
# 1. DatabaseManager Tests
# ============================================================

class TestDatabaseManager:
    """Tests for src/database/connection.DatabaseManager."""

    def _fresh_cls(self):
        """Return DatabaseManager class with reset class-level state."""
        from src.database.connection import DatabaseManager
        # Reset singleton/class state so each test is isolated
        DatabaseManager._instance = None
        DatabaseManager._engine = None
        DatabaseManager._session_factory = None
        return DatabaseManager

    # ----------------------------------------------------------
    # get_database_url
    # ----------------------------------------------------------

    def test_get_database_url_from_individual_vars(self):
        """Build URL from POSTGRES_* env vars."""
        cls = self._fresh_cls()
        env = {
            "POSTGRES_HOST": "db.example.com",
            "POSTGRES_PORT": "5433",
            "POSTGRES_USER": "myuser",
            "POSTGRES_PASSWORD": "secret",
            "POSTGRES_DB": "mydb",
        }
        with patch.dict("os.environ", env, clear=True):
            url = cls.get_database_url()
        assert url == "postgresql+asyncpg://myuser:secret@db.example.com:5433/mydb"

    def test_get_database_url_missing_password_raises(self):
        """Raise ValueError when no password is available."""
        cls = self._fresh_cls()
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="POSTGRES_PASSWORD"):
                cls.get_database_url()

    def test_get_database_url_from_database_url_env(self):
        """Convert postgresql:// to postgresql+asyncpg:// from DATABASE_URL."""
        cls = self._fresh_cls()
        env = {"DATABASE_URL": "postgresql://u:p@host:5432/db"}
        with patch.dict("os.environ", env, clear=True):
            url = cls.get_database_url()
        assert url == "postgresql+asyncpg://u:p@host:5432/db"

    def test_get_database_url_postgres_prefix(self):
        """Convert postgres:// (Heroku-style) to postgresql+asyncpg://."""
        cls = self._fresh_cls()
        env = {"DATABASE_URL": "postgres://u:p@host:5432/db"}
        with patch.dict("os.environ", env, clear=True):
            url = cls.get_database_url()
        assert url == "postgresql+asyncpg://u:p@host:5432/db"

    def test_get_database_url_cloudsql_unix_socket(self):
        """Prefer Cloud SQL Proxy Unix socket when CLOUDSQL_INSTANCE is set."""
        cls = self._fresh_cls()
        env = {
            "CLOUDSQL_INSTANCE": "project:region:instance",
            "POSTGRES_USER": "admin",
            "POSTGRES_PASSWORD": "pw",
            "POSTGRES_DB": "xdrdb",
        }
        with patch.dict("os.environ", env, clear=True):
            url = cls.get_database_url()
        assert "asyncpg" in url
        assert "admin" in url
        assert "xdrdb" in url

    # ----------------------------------------------------------
    # initialize / close
    # ----------------------------------------------------------

    @pytest.mark.asyncio
    async def test_initialize_creates_engine(self):
        """initialize() should set _engine and _session_factory."""
        cls = self._fresh_cls()
        fake_engine = MagicMock()
        fake_engine.dispose = AsyncMock()

        with patch(
            "src.database.connection.create_async_engine",
            return_value=fake_engine,
        ) as mock_create, patch(
            "src.database.connection.async_sessionmaker",
            return_value=MagicMock(),
        ):
            await cls.initialize(database_url="postgresql+asyncpg://u:p@localhost/db")

        assert cls._engine is fake_engine
        assert cls._session_factory is not None

        # cleanup
        cls._engine = None
        cls._session_factory = None

    @pytest.mark.asyncio
    async def test_initialize_skips_when_already_initialized(self):
        """initialize() with existing engine (no force_reconnect) should be a no-op."""
        cls = self._fresh_cls()
        cls._engine = MagicMock()  # simulate already initialised

        with patch("src.database.connection.create_async_engine") as mock_create:
            await cls.initialize(database_url="postgresql+asyncpg://u:p@localhost/db")
        mock_create.assert_not_called()

        # cleanup
        cls._engine = None
        cls._session_factory = None

    @pytest.mark.asyncio
    async def test_initialize_force_reconnect(self):
        """force_reconnect should dispose old engine and create new one."""
        cls = self._fresh_cls()
        old_engine = MagicMock()
        old_engine.dispose = AsyncMock()
        cls._engine = old_engine

        new_engine = MagicMock()
        new_engine.dispose = AsyncMock()

        with patch(
            "src.database.connection.create_async_engine",
            return_value=new_engine,
        ), patch(
            "src.database.connection.async_sessionmaker",
            return_value=MagicMock(),
        ):
            await cls.initialize(
                database_url="postgresql+asyncpg://u:p@localhost/db",
                force_reconnect=True,
            )

        old_engine.dispose.assert_awaited_once()
        assert cls._engine is new_engine

        # cleanup
        cls._engine = None
        cls._session_factory = None

    @pytest.mark.asyncio
    async def test_close_disposes_engine(self):
        """close() should dispose engine and reset state."""
        cls = self._fresh_cls()
        mock_engine = MagicMock()
        mock_engine.dispose = AsyncMock()
        cls._engine = mock_engine
        cls._session_factory = MagicMock()

        await cls.close()

        mock_engine.dispose.assert_awaited_once()
        assert cls._engine is None
        assert cls._session_factory is None

    @pytest.mark.asyncio
    async def test_close_noop_when_not_initialized(self):
        """close() should be safe when no engine exists."""
        cls = self._fresh_cls()
        await cls.close()  # should not raise

    # ----------------------------------------------------------
    # get_session context manager
    # ----------------------------------------------------------

    @pytest.mark.asyncio
    async def test_get_session_raises_when_not_initialized(self):
        """get_session() should raise RuntimeError if DB not initialized."""
        cls = self._fresh_cls()
        with pytest.raises(RuntimeError, match="Database not initialized"):
            async with cls.get_session():
                pass

    @pytest.mark.asyncio
    async def test_get_session_commits_on_success(self):
        """Session should commit and close on successful exit."""
        cls = self._fresh_cls()
        mock_session = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()

        cls._session_factory = MagicMock(return_value=mock_session)

        async with cls.get_session() as session:
            assert session is mock_session

        mock_session.commit.assert_awaited_once()
        mock_session.close.assert_awaited_once()
        mock_session.rollback.assert_not_awaited()

        # cleanup
        cls._session_factory = None

    @pytest.mark.asyncio
    async def test_get_session_rollbacks_on_error(self):
        """Session should rollback on exception and re-raise."""
        cls = self._fresh_cls()
        mock_session = AsyncMock()
        mock_session.commit = AsyncMock(side_effect=Exception("db error"))
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()

        cls._session_factory = MagicMock(return_value=mock_session)

        with pytest.raises(Exception, match="db error"):
            async with cls.get_session() as session:
                pass  # commit is called on exit, which raises

        mock_session.rollback.assert_awaited_once()
        mock_session.close.assert_awaited_once()

        # cleanup
        cls._session_factory = None

    # ----------------------------------------------------------
    # get_pool_stats
    # ----------------------------------------------------------

    def test_get_pool_stats_not_initialized(self):
        """Pool stats should indicate not_initialized when no engine."""
        cls = self._fresh_cls()
        stats = cls.get_pool_stats()
        assert stats == {"status": "not_initialized"}

    def test_get_pool_stats_active(self):
        """Pool stats should return active stats from engine."""
        cls = self._fresh_cls()
        mock_pool = MagicMock()
        mock_pool.size.return_value = 20
        mock_pool.checkedout.return_value = 5
        mock_pool.overflow.return_value = 2
        mock_pool.checkedin.return_value = 15

        mock_engine = MagicMock()
        mock_engine.pool = mock_pool
        cls._engine = mock_engine

        stats = cls.get_pool_stats()
        assert stats["status"] == "active"
        assert stats["pool_size"] == 20
        assert stats["checked_out"] == 5
        assert stats["overflow"] == 2
        assert stats["checked_in"] == 15
        assert stats["total"] == 22  # size + overflow

        # cleanup
        cls._engine = None

    def test_get_pool_stats_handles_error(self):
        """Pool stats should return error dict if pool access fails."""
        cls = self._fresh_cls()
        mock_engine = MagicMock()
        type(mock_engine).pool = PropertyMock(side_effect=RuntimeError("pool gone"))
        cls._engine = mock_engine

        stats = cls.get_pool_stats()
        assert stats["status"] == "error"
        assert "pool gone" in stats["detail"]

        # cleanup
        cls._engine = None

    # ----------------------------------------------------------
    # health_check
    # ----------------------------------------------------------

    @pytest.mark.asyncio
    async def test_health_check_returns_false_when_not_initialized(self):
        cls = self._fresh_cls()
        assert await cls.health_check() is False

    @pytest.mark.asyncio
    async def test_health_check_success(self):
        cls = self._fresh_cls()
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()
        cls._session_factory = MagicMock(return_value=mock_session)

        result = await cls.health_check()
        assert result is True

        # cleanup
        cls._session_factory = None

    @pytest.mark.asyncio
    async def test_health_check_failure(self):
        cls = self._fresh_cls()
        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(side_effect=Exception("connection refused"))
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()
        cls._session_factory = MagicMock(return_value=mock_session)

        result = await cls.health_check()
        assert result is False

        # cleanup
        cls._session_factory = None


# ============================================================
# 2. DatabaseService Tests
# ============================================================

class TestDatabaseService:
    """Tests for src/database/service.DatabaseService CRUD operations."""

    # ----------------------------------------------------------
    # save_event
    # ----------------------------------------------------------

    @pytest.mark.asyncio
    async def test_save_event_success(self):
        """save_event should add model to session and return event_id."""
        from src.database.service import DatabaseService

        event_data = {
            "event_id": "evt-001",
            "chain_id": "ethereum",
            "event_type": "transfer",
            "tx_hash": "0xabc",
            "block_number": 100,
            "block_timestamp": datetime.now(timezone.utc),
            "severity": "LOW",
        }

        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()

        with patch(
            "src.database.service.DatabaseManager.get_session",
        ) as mock_get_session:
            # Build an async context manager that yields mock_session
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=mock_session)
            ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_session.return_value = ctx

            result = await DatabaseService.save_event(event_data)

        mock_session.add.assert_called_once()
        mock_session.flush.assert_awaited_once()
        assert result == "evt-001"

    @pytest.mark.asyncio
    async def test_save_event_failure_raises(self):
        """save_event should propagate exceptions from session."""
        from src.database.service import DatabaseService

        event_data = {
            "event_id": "evt-002",
            "chain_id": "ethereum",
            "event_type": "transfer",
            "tx_hash": "0xdef",
            "block_number": 101,
        }

        mock_session = AsyncMock()
        mock_session.add = MagicMock()
        mock_session.flush = AsyncMock(side_effect=Exception("integrity error"))
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()

        with patch(
            "src.database.service.DatabaseManager.get_session",
        ) as mock_get_session:
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=mock_session)
            ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_session.return_value = ctx

            with pytest.raises(Exception, match="integrity error"):
                await DatabaseService.save_event(event_data)

    # ----------------------------------------------------------
    # save_events_batch
    # ----------------------------------------------------------

    @pytest.mark.asyncio
    async def test_save_events_batch_empty(self):
        """save_events_batch with empty list returns 0 immediately."""
        from src.database.service import DatabaseService
        result = await DatabaseService.save_events_batch([])
        assert result == 0

    @pytest.mark.asyncio
    async def test_save_events_batch_success(self):
        """save_events_batch should save events and return count."""
        from src.database.service import DatabaseService

        events = [
            {
                "event_id": "evt-batch-1",
                "chain_id": "ethereum",
                "event_type": "transfer",
                "tx_hash": "0x111",
                "block_number": 200,
                "severity": "LOW",
            },
            {
                "event_id": "evt-batch-2",
                "chain_id": "ethereum",
                "event_type": "mint",
                "tx_hash": "0x222",
                "block_number": 201,
                "severity": "HIGH",
            },
        ]

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock()
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()

        # Mock savepoint (begin_nested)
        mock_savepoint = AsyncMock()
        mock_savepoint.commit = AsyncMock()
        mock_savepoint.rollback = AsyncMock()
        mock_session.begin_nested = AsyncMock(return_value=mock_savepoint)

        with patch(
            "src.database.service.DatabaseManager.get_session",
        ) as mock_get_session:
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=mock_session)
            ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_session.return_value = ctx

            result = await DatabaseService.save_events_batch(events)

        # Should have saved both events
        assert result == 2

    # ----------------------------------------------------------
    # get_tenant_by_api_key
    # ----------------------------------------------------------

    @pytest.mark.asyncio
    async def test_get_tenant_by_api_key_not_found(self):
        """Returns None when key hash is not in database."""
        from src.database.service import DatabaseService

        mock_result = MagicMock()
        mock_result.fetchone.return_value = None

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()

        with patch(
            "src.database.service.DatabaseManager.get_session",
        ) as mock_get_session:
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=mock_session)
            ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_session.return_value = ctx

            result = await DatabaseService.get_tenant_by_api_key("deadbeef")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_tenant_by_api_key_inactive_customer(self):
        """Returns None when customer is inactive."""
        from src.database.service import DatabaseService

        mock_result = MagicMock()
        # (customer_id, tier, customer_active, scopes, key_status, expires_at)
        mock_result.fetchone.return_value = (
            "cust-1", "pro", False, ["read"], "active", None
        )

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()

        with patch(
            "src.database.service.DatabaseManager.get_session",
        ) as mock_get_session:
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=mock_session)
            ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_session.return_value = ctx

            result = await DatabaseService.get_tenant_by_api_key("somehash")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_tenant_by_api_key_success(self):
        """Returns tenant dict for valid, active key."""
        from src.database.service import DatabaseService

        mock_result = MagicMock()
        mock_result.fetchone.return_value = (
            "cust-1", "enterprise", True, ["read", "write"], "active", None
        )

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)
        mock_session.commit = AsyncMock()
        mock_session.rollback = AsyncMock()
        mock_session.close = AsyncMock()

        with patch(
            "src.database.service.DatabaseManager.get_session",
        ) as mock_get_session:
            ctx = AsyncMock()
            ctx.__aenter__ = AsyncMock(return_value=mock_session)
            ctx.__aexit__ = AsyncMock(return_value=False)
            mock_get_session.return_value = ctx

            result = await DatabaseService.get_tenant_by_api_key("validhash")

        assert result is not None
        assert result["customer_id"] == "cust-1"
        assert result["tier"] == "enterprise"
        assert "read" in result["scopes"]

    # ----------------------------------------------------------
    # get_tenant_usage_stats
    # ----------------------------------------------------------

    @pytest.mark.asyncio
    async def test_get_tenant_usage_stats_returns_zeros_on_error(self):
        """Should return zero-valued dict when DB call fails."""
        from src.database.service import DatabaseService

        with patch(
            "src.database.service.DatabaseManager.get_session",
            side_effect=Exception("connection lost"),
        ):
            result = await DatabaseService.get_tenant_usage_stats("cust-1")

        assert result["customer_id"] == "cust-1"
        assert result["events_count"] == 0


# ============================================================
# 3. Event Bus Tests (InMemoryBus)
# ============================================================

class TestInMemoryBus:
    """Tests for src/pipeline/bus.InMemoryBus."""

    @pytest.mark.asyncio
    async def test_publish_and_consume(self):
        """Basic publish then consume flow."""
        from src.pipeline.bus import InMemoryBus

        bus = InMemoryBus(max_size=100)
        event = {"chain_id": "ethereum", "tx_hash": "0x1", "log_index": 0}

        published = await bus.publish(event, idempotency_key="key-1")
        assert published is True

        depth = await bus.get_queue_depth()
        assert depth == 1

        messages = await bus.consume(batch_size=5)
        assert len(messages) == 1
        assert messages[0].event_data == event
        assert messages[0].idempotency_key == "key-1"

    @pytest.mark.asyncio
    async def test_publish_deduplication(self):
        """Duplicate idempotency key should be rejected."""
        from src.pipeline.bus import InMemoryBus

        bus = InMemoryBus(max_size=100)
        event = {"chain_id": "ethereum", "tx_hash": "0x2", "log_index": 0}

        assert await bus.publish(event, idempotency_key="dup-key") is True
        assert await bus.publish(event, idempotency_key="dup-key") is False

        assert await bus.get_queue_depth() == 1

    @pytest.mark.asyncio
    async def test_publish_auto_idempotency_key(self):
        """When no key provided, one is generated from event fields."""
        from src.pipeline.bus import InMemoryBus

        bus = InMemoryBus(max_size=100)
        event = {"chain_id": "ethereum", "tx_hash": "0x3", "log_index": 0}

        assert await bus.publish(event) is True
        # Same event again => duplicate
        assert await bus.publish(event) is False

    @pytest.mark.asyncio
    async def test_publish_queue_full_never_policy(self):
        """Queue full with 'never' drop policy returns False."""
        from src.pipeline.bus import InMemoryBus

        bus = InMemoryBus(max_size=2)
        # Fill queue
        await bus.publish({"chain_id": "a", "tx_hash": "0x1"}, idempotency_key="k1")
        await bus.publish({"chain_id": "a", "tx_hash": "0x2"}, idempotency_key="k2")

        # Third event should fail (default policy is "never")
        with patch("src.pipeline.bus.QUEUE_DROP_POLICY", "never"):
            result = await bus.publish(
                {"chain_id": "a", "tx_hash": "0x3"}, idempotency_key="k3"
            )
        assert result is False

    @pytest.mark.asyncio
    async def test_publish_queue_full_oldest_policy(self):
        """Queue full with 'oldest' policy should drop oldest and accept new."""
        from src.pipeline.bus import InMemoryBus

        bus = InMemoryBus(max_size=2)
        await bus.publish({"chain_id": "a", "tx_hash": "0x1"}, idempotency_key="k1")
        await bus.publish({"chain_id": "a", "tx_hash": "0x2"}, idempotency_key="k2")

        with patch("src.pipeline.bus.QUEUE_DROP_POLICY", "oldest"):
            result = await bus.publish(
                {"chain_id": "a", "tx_hash": "0x3"}, idempotency_key="k3"
            )
        assert result is True
        assert await bus.get_queue_depth() == 2  # still max_size

    @pytest.mark.asyncio
    async def test_consume_empty_queue(self):
        """Consuming from empty queue returns empty list."""
        from src.pipeline.bus import InMemoryBus

        bus = InMemoryBus()
        messages = await bus.consume(batch_size=10)
        assert messages == []

    @pytest.mark.asyncio
    async def test_consume_respects_batch_size(self):
        """consume() should return at most batch_size messages."""
        from src.pipeline.bus import InMemoryBus

        bus = InMemoryBus(max_size=100)
        for i in range(5):
            await bus.publish(
                {"chain_id": "eth", "tx_hash": f"0x{i}"},
                idempotency_key=f"key-{i}",
            )

        messages = await bus.consume(batch_size=3)
        assert len(messages) == 3

        # Remaining 2
        messages = await bus.consume(batch_size=10)
        assert len(messages) == 2

    @pytest.mark.asyncio
    async def test_close_clears_state(self):
        """close() should empty queue and processed keys."""
        from src.pipeline.bus import InMemoryBus

        bus = InMemoryBus()
        await bus.publish(
            {"chain_id": "eth", "tx_hash": "0x1"},
            idempotency_key="k1",
        )
        await bus.close()

        assert await bus.get_queue_depth() == 0
        assert len(bus.processed_keys) == 0

    # ----------------------------------------------------------
    # BusMessage serialization
    # ----------------------------------------------------------

    def test_bus_message_round_trip(self):
        """BusMessage.to_dict / from_dict should round-trip."""
        from src.pipeline.bus import BusMessage

        msg = BusMessage(
            id="test-1",
            event_data={"chain_id": "eth"},
            idempotency_key="idem-1",
        )
        d = msg.to_dict()
        restored = BusMessage.from_dict(d)

        assert restored.id == msg.id
        assert restored.event_data == msg.event_data
        assert restored.idempotency_key == msg.idempotency_key

    # ----------------------------------------------------------
    # create_event_bus factory
    # ----------------------------------------------------------

    def test_create_event_bus_in_memory_when_no_redis(self):
        """Factory returns InMemoryBus when REDIS_URL is empty."""
        from src.pipeline.bus import InMemoryBus

        with patch("src.pipeline.bus.REDIS_URL", ""):
            from src.pipeline.bus import create_event_bus
            bus = create_event_bus()
        assert isinstance(bus, InMemoryBus)


# ============================================================
# 4. TelegramAlerter Tests
# ============================================================

class TestTelegramAlerter:
    """Tests for src/response/telegram.TelegramAlerter."""

    def _make_incident(self, **overrides):
        """Create a minimal Incident for testing."""
        from src.models.incidents import Incident
        from src.models.events import Severity

        defaults = dict(
            id="inc-001",
            severity=Severity.CRITICAL,
            affected_chains=["ethereum", "bsc"],
            total_loss_usd=5_000_000,
            tvl_at_risk_usd=50_000_000,
        )
        defaults.update(overrides)
        return Incident(**defaults)

    def _make_explanation(self, **overrides):
        """Create a minimal Explanation for testing."""
        from src.explainability.explanation import Explanation, RecommendedAction

        defaults = dict(
            incident_id="inc-001",
            title="Unbacked Mint on Bridge",
            confidence=0.95,
            what_happened="Attacker minted 5M USDC without locking collateral on the source chain.",
            recommended_actions=[
                RecommendedAction(
                    priority=1,
                    action="Pause bridge immediately",
                    reason="Active exploit",
                    is_urgent=True,
                ),
                RecommendedAction(
                    priority=2,
                    action="Revoke attacker approval",
                    reason="Prevent further drain",
                    is_urgent=True,
                ),
            ],
        )
        defaults.update(overrides)
        return Explanation(**defaults)

    # ----------------------------------------------------------
    # Message formatting
    # ----------------------------------------------------------

    def test_format_critical_message(self):
        """Critical message should contain key incident fields."""
        from src.response.telegram import TelegramAlerter

        alerter = TelegramAlerter(dashboard_url="https://xdr.test.com")
        incident = self._make_incident()
        explanation = self._make_explanation()

        message = alerter._format_critical_message(incident, explanation)

        assert "CRITICAL SECURITY ALERT" in message
        assert "Unbacked Mint on Bridge" in message
        assert "95%" in message  # confidence
        assert "ethereum" in message
        assert "$5,000,000" in message
        assert "xdr.test.com" in message

    def test_format_high_message(self):
        """High severity message should contain summary and actions."""
        from src.response.telegram import TelegramAlerter
        from src.models.events import Severity

        alerter = TelegramAlerter()
        incident = self._make_incident(severity=Severity.HIGH)
        explanation = self._make_explanation()

        message = alerter._format_high_message(incident, explanation)

        assert "HIGH SEVERITY ALERT" in message
        assert "Unbacked Mint" in message
        assert "$5,000,000" in message

    def test_format_info_message(self):
        """Info message should be concise."""
        from src.response.telegram import TelegramAlerter
        from src.models.events import Severity

        alerter = TelegramAlerter()
        incident = self._make_incident(severity=Severity.MEDIUM)
        explanation = self._make_explanation()

        message = alerter._format_info_message(incident, explanation)

        assert "Security Alert" in message
        assert "Unbacked Mint" in message

    def test_format_urgent_actions(self):
        """Urgent actions should list only is_urgent actions."""
        from src.response.telegram import TelegramAlerter
        from src.explainability.explanation import RecommendedAction

        alerter = TelegramAlerter()
        explanation = self._make_explanation()

        text = alerter._format_urgent_actions(explanation)
        assert "Pause bridge" in text
        assert "Revoke attacker" in text

    def test_format_urgent_actions_fallback(self):
        """When no urgent actions, use fallback text."""
        from src.response.telegram import TelegramAlerter

        alerter = TelegramAlerter()
        explanation = self._make_explanation(recommended_actions=[])

        text = alerter._format_urgent_actions(explanation)
        assert "Review incident immediately" in text

    def test_format_actions_empty(self):
        """When no actions, use fallback."""
        from src.response.telegram import TelegramAlerter

        alerter = TelegramAlerter()
        explanation = self._make_explanation(recommended_actions=[])

        text = alerter._format_actions(explanation)
        assert "Review incident details" in text

    # ----------------------------------------------------------
    # send_critical
    # ----------------------------------------------------------

    @pytest.mark.asyncio
    async def test_send_critical_with_bot(self):
        """send_critical should call bot.send_message when bot + channel configured."""
        from src.response.telegram import TelegramAlerter

        mock_bot = AsyncMock()
        mock_bot.send_message = AsyncMock()

        alerter = TelegramAlerter(
            bot_token="fake-token",
            critical_channel="-100123456",
        )
        alerter._bot = mock_bot  # inject mock directly

        incident = self._make_incident()
        explanation = self._make_explanation()

        await alerter.send_critical(incident, explanation)

        mock_bot.send_message.assert_awaited_once()
        call_kwargs = mock_bot.send_message.call_args
        assert call_kwargs.kwargs["chat_id"] == "-100123456"
        assert call_kwargs.kwargs["parse_mode"] == "HTML"

    @pytest.mark.asyncio
    async def test_send_critical_without_bot_logs(self):
        """send_critical without bot should log instead of sending."""
        from src.response.telegram import TelegramAlerter

        alerter = TelegramAlerter()  # no bot_token

        incident = self._make_incident()
        explanation = self._make_explanation()

        # Should not raise
        await alerter.send_critical(incident, explanation)

    @pytest.mark.asyncio
    async def test_send_critical_handles_send_error(self):
        """send_critical should catch and log bot.send_message errors."""
        from src.response.telegram import TelegramAlerter

        mock_bot = AsyncMock()
        mock_bot.send_message = AsyncMock(side_effect=Exception("network timeout"))

        alerter = TelegramAlerter(
            bot_token="fake-token",
            critical_channel="-100123456",
        )
        alerter._bot = mock_bot

        incident = self._make_incident()
        explanation = self._make_explanation()

        # Should not raise
        await alerter.send_critical(incident, explanation)

    # ----------------------------------------------------------
    # send_high / send_info
    # ----------------------------------------------------------

    @pytest.mark.asyncio
    async def test_send_high_uses_general_channel(self):
        """send_high should prefer general_channel."""
        from src.response.telegram import TelegramAlerter

        mock_bot = AsyncMock()
        mock_bot.send_message = AsyncMock()

        alerter = TelegramAlerter(
            bot_token="fake",
            critical_channel="-100crit",
            general_channel="-100gen",
        )
        alerter._bot = mock_bot

        await alerter.send_high(self._make_incident(), self._make_explanation())

        call_kwargs = mock_bot.send_message.call_args
        assert call_kwargs.kwargs["chat_id"] == "-100gen"

    @pytest.mark.asyncio
    async def test_send_high_falls_back_to_critical_channel(self):
        """send_high should fallback to critical_channel when no general."""
        from src.response.telegram import TelegramAlerter

        mock_bot = AsyncMock()
        mock_bot.send_message = AsyncMock()

        alerter = TelegramAlerter(
            bot_token="fake",
            critical_channel="-100crit",
        )
        alerter._bot = mock_bot

        await alerter.send_high(self._make_incident(), self._make_explanation())

        call_kwargs = mock_bot.send_message.call_args
        assert call_kwargs.kwargs["chat_id"] == "-100crit"

    @pytest.mark.asyncio
    async def test_send_info_with_bot(self):
        """send_info should send to general_channel."""
        from src.response.telegram import TelegramAlerter

        mock_bot = AsyncMock()
        mock_bot.send_message = AsyncMock()

        alerter = TelegramAlerter(
            bot_token="fake",
            general_channel="-100gen",
        )
        alerter._bot = mock_bot

        await alerter.send_info(self._make_incident(), self._make_explanation())

        mock_bot.send_message.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_info_no_channel_is_silent(self):
        """send_info without general_channel should do nothing."""
        from src.response.telegram import TelegramAlerter

        mock_bot = AsyncMock()
        alerter = TelegramAlerter(bot_token="fake")
        alerter._bot = mock_bot

        # Should not raise
        await alerter.send_info(self._make_incident(), self._make_explanation())
        mock_bot.send_message.assert_not_awaited()

    # ----------------------------------------------------------
    # _get_bot
    # ----------------------------------------------------------

    @pytest.mark.asyncio
    async def test_get_bot_no_token_returns_none(self):
        """_get_bot with no token returns None."""
        from src.response.telegram import TelegramAlerter

        alerter = TelegramAlerter()
        bot = await alerter._get_bot()
        assert bot is None

    @pytest.mark.asyncio
    async def test_get_bot_import_error_returns_none(self):
        """_get_bot should handle missing telegram library gracefully."""
        import sys
        from src.response.telegram import TelegramAlerter

        alerter = TelegramAlerter(bot_token="fake-token")

        # Temporarily make "from telegram import Bot" fail by inserting
        # a None entry into sys.modules (standard way to simulate
        # a missing package).
        had_telegram = "telegram" in sys.modules
        original = sys.modules.get("telegram")
        sys.modules["telegram"] = None  # triggers ImportError on import

        try:
            bot = await alerter._get_bot()
            assert bot is None
        finally:
            # Restore
            if had_telegram:
                sys.modules["telegram"] = original
            else:
                sys.modules.pop("telegram", None)

    @pytest.mark.asyncio
    async def test_get_bot_caches_instance(self):
        """_get_bot should return cached bot on second call."""
        from src.response.telegram import TelegramAlerter

        alerter = TelegramAlerter(bot_token="fake-token")
        mock_bot = MagicMock()
        alerter._bot = mock_bot

        result = await alerter._get_bot()
        assert result is mock_bot


# ============================================================
# 5. Prometheus Metrics Collector Tests
# ============================================================

class TestXDRMetrics:
    """Tests for src/metrics/collector.XDRMetrics and helper functions.

    Each test uses a unique namespace to avoid Prometheus
    'Duplicated timeseries' errors across test runs.
    """

    _counter = 0

    @classmethod
    def _unique_ns(cls):
        cls._counter += 1
        return f"test_xdr_{cls._counter}_{int(time.time() * 1000) % 100000}"

    def test_initialization(self):
        """XDRMetrics should initialize all metric families."""
        from src.metrics.collector import XDRMetrics

        ns = self._unique_ns()
        m = XDRMetrics(namespace=ns)

        assert m.namespace == ns
        assert m.events_total is not None
        assert m.incidents_total is not None
        assert m.chain_connected is not None
        assert m.api_requests_total is not None
        assert m.uptime_seconds is not None

    def test_events_total_increment(self):
        """Counter events_total should increment correctly."""
        from src.metrics.collector import XDRMetrics

        ns = self._unique_ns()
        m = XDRMetrics(namespace=ns)

        m.events_total.labels(chain="ethereum", event_type="transfer").inc()
        m.events_total.labels(chain="ethereum", event_type="transfer").inc()

        # Read the counter value
        val = m.events_total.labels(chain="ethereum", event_type="transfer")._value.get()
        assert val == 2.0

    def test_gauge_set(self):
        """Gauge should reflect set values."""
        from src.metrics.collector import XDRMetrics

        ns = self._unique_ns()
        m = XDRMetrics(namespace=ns)

        m.chain_connected.labels(chain="bsc").set(1)
        val = m.chain_connected.labels(chain="bsc")._value.get()
        assert val == 1.0

        m.chain_connected.labels(chain="bsc").set(0)
        val = m.chain_connected.labels(chain="bsc")._value.get()
        assert val == 0.0

    def test_histogram_observe(self):
        """Histogram should accept observations without errors."""
        from src.metrics.collector import XDRMetrics

        ns = self._unique_ns()
        m = XDRMetrics(namespace=ns)

        # Should not raise
        m.event_processing_time.labels(chain="ethereum").observe(0.05)
        m.event_processing_time.labels(chain="ethereum").observe(0.1)

    def test_update_uptime(self):
        """update_uptime should set a positive value."""
        from src.metrics.collector import XDRMetrics

        ns = self._unique_ns()
        m = XDRMetrics(namespace=ns)

        m.update_uptime()
        val = m.uptime_seconds._value.get()
        assert val >= 0

    def test_get_metrics_returns_bytes(self):
        """get_metrics should return Prometheus-formatted bytes."""
        from src.metrics.collector import XDRMetrics

        ns = self._unique_ns()
        m = XDRMetrics(namespace=ns)

        data = m.get_metrics()
        assert isinstance(data, bytes)
        assert len(data) > 0

    def test_get_content_type(self):
        """Content type should be the Prometheus text format."""
        from src.metrics.collector import XDRMetrics

        ns = self._unique_ns()
        m = XDRMetrics(namespace=ns)

        ct = m.get_content_type()
        assert "text/plain" in ct or "text/openmetrics" in ct or "text/" in ct

    def test_info_metric(self):
        """Info metric should contain build information."""
        from src.metrics.collector import XDRMetrics

        ns = self._unique_ns()
        m = XDRMetrics(namespace=ns)

        data = m.get_metrics().decode()
        assert f"{ns}_build_info" in data

    # ----------------------------------------------------------
    # Helper functions
    # ----------------------------------------------------------

    def test_track_event_helper(self):
        """track_event should increment events_total."""
        from src.metrics.collector import track_event, metrics

        # Use the global metrics instance
        before = metrics.events_total.labels(
            chain="polygon", event_type="lock"
        )._value.get()

        track_event("polygon", "lock", processing_time=0.02)

        after = metrics.events_total.labels(
            chain="polygon", event_type="lock"
        )._value.get()

        assert after == before + 1

    def test_track_incident_helper(self):
        """track_incident should increment incidents_total."""
        from src.metrics.collector import track_incident, metrics

        before = metrics.incidents_total.labels(
            severity="HIGH", chain="ethereum", rule_id="rule-1"
        )._value.get()

        track_incident("HIGH", "ethereum", "rule-1", detection_time=1.5)

        after = metrics.incidents_total.labels(
            severity="HIGH", chain="ethereum", rule_id="rule-1"
        )._value.get()

        assert after == before + 1

    def test_track_chain_status_helper(self):
        """track_chain_status should set chain_connected gauge."""
        from src.metrics.collector import track_chain_status, metrics

        track_chain_status("avalanche", connected=True, block_height=1000, latency=0.05)

        val = metrics.chain_connected.labels(chain="avalanche")._value.get()
        assert val == 1.0

        bh = metrics.chain_block_height.labels(chain="avalanche")._value.get()
        assert bh == 1000

    def test_track_api_request_helper(self):
        """track_api_request should increment api_requests_total."""
        from src.metrics.collector import track_api_request, metrics

        before = metrics.api_requests_total.labels(
            method="GET", endpoint="/events", status="200"
        )._value.get()

        track_api_request("GET", "/events", 200, 0.15)

        after = metrics.api_requests_total.labels(
            method="GET", endpoint="/events", status="200"
        )._value.get()

        assert after == before + 1

    def test_track_db_query_helper(self):
        """track_db_query should observe duration in histogram."""
        from src.metrics.collector import track_db_query

        # Should not raise
        track_db_query("SELECT", "events", 0.025)

    def test_set_event_backlog_helper(self):
        """set_event_backlog should set gauge value."""
        from src.metrics.collector import set_event_backlog, metrics

        set_event_backlog("ethereum", 42)
        val = metrics.event_backlog_size.labels(chain="ethereum")._value.get()
        assert val == 42

    def test_update_db_pool_metrics_helper(self):
        """update_db_pool_metrics should set pool gauges."""
        from src.metrics.collector import update_db_pool_metrics, metrics

        pool_stats = {
            "status": "active",
            "pool_size": 20,
            "checked_out": 3,
            "overflow": 1,
            "checked_in": 17,
        }
        update_db_pool_metrics(pool_stats)

        assert metrics.db_pool_size._value.get() == 20
        assert metrics.db_pool_checked_out._value.get() == 3
        assert metrics.db_pool_overflow._value.get() == 1
        assert metrics.db_pool_available._value.get() == 17

    def test_update_db_pool_metrics_inactive_noop(self):
        """update_db_pool_metrics should skip when status is not 'active'."""
        from src.metrics.collector import update_db_pool_metrics, metrics

        # Set to known value first
        metrics.db_pool_size.set(99)
        update_db_pool_metrics({"status": "not_initialized"})
        # Should remain unchanged
        assert metrics.db_pool_size._value.get() == 99

    # ----------------------------------------------------------
    # Decorators
    # ----------------------------------------------------------

    def test_measure_time_decorator(self):
        """measure_time decorator should not alter function result."""
        from src.metrics.collector import measure_time

        @measure_time("test_op")
        def add(a, b):
            return a + b

        assert add(2, 3) == 5

    @pytest.mark.asyncio
    async def test_async_measure_time_decorator(self):
        """async_measure_time decorator should not alter async function result."""
        from src.metrics.collector import async_measure_time

        @async_measure_time("test_async_op")
        async def async_add(a, b):
            return a + b

        assert await async_add(2, 3) == 5
