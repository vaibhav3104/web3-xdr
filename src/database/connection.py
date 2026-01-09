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
    async def initialize(cls, database_url: Optional[str] = None) -> None:
        """
        Initialize the database engine and session factory.
        """
        if cls._engine is not None:
            logger.warning("database_already_initialized")
            return
        
        url = database_url or cls.get_database_url()
        
        logger.info("initializing_database", url=url.split("@")[-1])  # Log without password
        
        cls._engine = create_async_engine(
            url,
            echo=os.getenv("SQL_ECHO", "false").lower() == "true",
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
            pool_pre_ping=True,  # Test connections before use
            pool_recycle=3600,   # Recycle connections after 1 hour
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

