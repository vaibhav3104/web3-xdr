"""
PostgreSQL Database Connection Manager.
Handles async connection pooling and session management.
"""

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

import structlog
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.pool import NullPool

logger = structlog.get_logger()


class DatabaseManager:
    """
    Manages PostgreSQL database connections using SQLAlchemy async.
    """
    
    _instance: Optional["DatabaseManager"] = None
    _engine: Optional[AsyncEngine] = None
    _session_factory: Optional[async_sessionmaker] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def get_database_url(cls) -> str:
        """
        Build database URL from environment variables.
        Prioritizes DATABASE_URL if set (for Cloud SQL).
        """
        # Check DATABASE_URL first (Cloud SQL format)
        database_url = os.getenv("DATABASE_URL")
        if database_url:
            # Convert postgresql:// to postgresql+asyncpg:// for asyncpg driver
            if database_url.startswith("postgresql://"):
                database_url = database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
            elif database_url.startswith("postgres://"):
                database_url = database_url.replace("postgres://", "postgresql+asyncpg://", 1)
            return database_url
        
        # Fall back to individual env vars
        host = os.getenv("POSTGRES_HOST", "localhost")
        port = os.getenv("POSTGRES_PORT", "5432")
        user = os.getenv("POSTGRES_USER", "xdr")
        password = os.getenv("POSTGRES_PASSWORD", "xdr_password")
        database = os.getenv("POSTGRES_DB", "web3_xdr")
        
        # Use asyncpg driver for async support
        return f"postgresql+asyncpg://{user}:{password}@{host}:{port}/{database}"
    
    @classmethod
    async def initialize(cls, database_url: Optional[str] = None, force_reconnect: bool = False) -> None:
        """
        Initialize the database engine and session factory.
        
        Args:
            database_url: Optional database URL. If not provided, uses get_database_url().
            force_reconnect: If True, closes existing connections and reinitializes.
        """
        if cls._engine is not None and not force_reconnect:
            logger.warning("database_already_initialized")
            return
        
        # Close existing connections if forcing reconnect
        if force_reconnect and cls._engine is not None:
            await cls.close()
        
        url = database_url or cls.get_database_url()
        
        logger.info("initializing_database", url=url.split("@")[-1])  # Log without password
        
        cls._engine = create_async_engine(
            url,
            echo=os.getenv("SQL_ECHO", "false").lower() == "true",
            pool_size=int(os.getenv("DB_POOL_SIZE", "20")),  # Increased from 10 to 20 for high-throughput worker
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),  # Allow burst connections
            pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "30")),  # Wait 30s before giving up on a connection
            pool_pre_ping=True,  # Test connections before use
            pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "1800")),  # Recycle connections every 30 mins to prevent stale sockets
        )
        
        cls._session_factory = async_sessionmaker(
            bind=cls._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )
        
        logger.info("database_initialized_successfully")
    
    @classmethod
    async def close(cls) -> None:
        """
        Close all database connections.
        """
        if cls._engine is not None:
            await cls._engine.dispose()
            cls._engine = None
            cls._session_factory = None
            logger.info("database_connections_closed")
    
    @classmethod
    @asynccontextmanager
    async def get_session(cls) -> AsyncGenerator[AsyncSession, None]:
        """
        Get an async database session.
        Usage:
            async with DatabaseManager.get_session() as session:
                # use session
        """
        if cls._session_factory is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        session = cls._session_factory()
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error("database_session_error", error=str(e))
            raise
        finally:
            await session.close()
    
    @classmethod
    async def create_tables(cls) -> None:
        """
        Create all database tables.
        """
        from .models import Base
        
        if cls._engine is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        async with cls._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("database_tables_created")
        
        # Apply performance indexes after table creation
        await cls.ensure_indexes()
    
    @classmethod
    async def ensure_indexes(cls) -> None:
        """
        Ensure performance indexes exist on the events table.
        Safe to call multiple times (uses CREATE INDEX IF NOT EXISTS).
        """
        if cls._engine is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        from sqlalchemy import text
        
        try:
            async with cls._engine.begin() as conn:
                # Index 1: For Timeline Sorting (Essential for API)
                await conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC);"
                ))
                logger.debug("index_created", index="idx_events_created_at")
                
                # Index 2: For Chain Filtering + Time (Essential for Dashboard)
                await conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS idx_events_chain_timestamp ON events(chain_id, block_timestamp DESC);"
                ))
                logger.debug("index_created", index="idx_events_chain_timestamp")
            
            logger.info("performance_indexes_ensured")
        except Exception as e:
            # Log but don't fail - indexes might already exist or table might not exist yet
            logger.warning("index_creation_warning", error=str(e))
    
    @classmethod
    async def drop_tables(cls) -> None:
        """
        Drop all database tables. USE WITH CAUTION!
        """
        from .models import Base
        
        if cls._engine is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        async with cls._engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        
        logger.warning("database_tables_dropped")


# Convenience function for dependency injection
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for FastAPI endpoints.
    Usage:
        @app.get("/")
        async def endpoint(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with DatabaseManager.get_session() as session:
        yield session

