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
        Prioritizes Cloud SQL Proxy Unix socket if available, then DATABASE_URL.
        """
        # Check if Cloud SQL Proxy is available (Cloud Run with cloudsql-instances annotation)
        # IMPORTANT: Check CLOUDSQL_INSTANCE FIRST, before DATABASE_URL
        # This ensures we use Unix socket even if DATABASE_URL is set
        cloudsql_instance = os.getenv("CLOUDSQL_INSTANCE")
        if cloudsql_instance:
            # Use Unix socket connection via Cloud SQL Proxy
            user = os.getenv("POSTGRES_USER") or os.getenv("DB_USER") or "xdr"
            password = os.getenv("POSTGRES_PASSWORD") or os.getenv("DB_PASSWORD") or ""
            database = os.getenv("POSTGRES_DB") or os.getenv("DB_NAME") or "web3_xdr"
            
            # Extract user/password from DATABASE_URL if available (but don't use the host/port)
            database_url = os.getenv("DATABASE_URL", "")
            if database_url and "@" in database_url:
                # Extract credentials from DATABASE_URL
                try:
                    # Format: postgresql://user:password@host:port/db
                    parts = database_url.split("@")
                    if len(parts) > 0:
                        cred_part = parts[0].split("//")[-1]
                        if ":" in cred_part:
                            user, password = cred_part.split(":", 1)
                        # Also check for database name after the @
                        if len(parts) > 1:
                            db_part = parts[1].split("/")
                            if len(db_part) > 1:
                                database = db_part[-1].split("?")[0]  # Remove query params
                except Exception as e:
                    logger.warning("failed_to_extract_creds_from_url", error=str(e))
            
            unix_socket_dir = f"/cloudsql/{cloudsql_instance}"
            logger.info("using_cloud_sql_proxy_unix_socket", instance=cloudsql_instance, socket_dir=unix_socket_dir, user=user, database=database)
            # asyncpg Unix socket format: postgresql+asyncpg://user:password@/database
            # No host/port in URL - will be set via connect_args in initialize()
            return f"postgresql+asyncpg://{user}:{password}@/{database}"
        
        # Check DATABASE_URL (for direct connection or when Cloud SQL Proxy not available)
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
        
        # Check if we should use Unix socket (Cloud SQL Proxy)
        cloudsql_instance = os.getenv("CLOUDSQL_INSTANCE")
        connect_args = {
            "server_settings": {
                "statement_timeout": "60000",  # 60 second query timeout at DB level
                "application_name": "web3-xdr"
            },
            "command_timeout": 60,  # asyncpg command timeout - increased to 60s
        }
        
        # If Cloud SQL Proxy is available, use Unix socket
        # For asyncpg with Cloud SQL Proxy, use the socket directory as host
        # The actual socket file will be .s.PGSQL.5432 in that directory
        if cloudsql_instance:
            unix_socket_dir = f"/cloudsql/{cloudsql_instance}"
            # asyncpg uses 'host' parameter for Unix socket directory
            # It will automatically look for .s.PGSQL.5432 in that directory
            connect_args["host"] = unix_socket_dir
            # Remove port for Unix socket connections
            connect_args.pop("port", None)
            logger.info("using_unix_socket_connection", socket_dir=unix_socket_dir, instance=cloudsql_instance)
        
        logger.info("initializing_database", url=url.split("@")[-1] if "@" in url else url)  # Log without password
        
        # Optimize connection pool settings
        cls._engine = create_async_engine(
            url,
            echo=os.getenv("SQL_ECHO", "false").lower() == "true",
            pool_size=int(os.getenv("DB_POOL_SIZE", "20")),  # Increased pool size
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),  # More overflow connections
            pool_timeout=int(os.getenv("DB_POOL_TIMEOUT", "60")),  # Increased to 60s for stability
            pool_pre_ping=True,  # Test connections before use
            pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "1800")),  # Recycle connections every 30 mins
            connect_args=connect_args
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
        Uses timeouts to prevent blocking.
        """
        if cls._engine is None:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        from sqlalchemy import text
        import asyncio
        
        try:
            # Use a separate connection with longer timeout for index creation
            async with cls._engine.begin() as conn:
                # Index 1: For Timeline Sorting (Essential for API)
                try:
                    await asyncio.wait_for(
                        conn.execute(text(
                            "CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC);"
                        )),
                        timeout=60.0  # 60 seconds for index creation
                    )
                    logger.info("index_created", index="idx_events_created_at")
                except asyncio.TimeoutError:
                    logger.warning("index_creation_timeout", index="idx_events_created_at")
                except Exception as e:
                    logger.warning("index_creation_error", index="idx_events_created_at", error=str(e))
                
                # Index 2: For Chain Filtering + Time (Essential for Dashboard)
                try:
                    await asyncio.wait_for(
                        conn.execute(text(
                            "CREATE INDEX IF NOT EXISTS idx_events_chain_timestamp ON events(chain_id, block_timestamp DESC);"
                        )),
                        timeout=60.0
                    )
                    logger.info("index_created", index="idx_events_chain_timestamp")
                except asyncio.TimeoutError:
                    logger.warning("index_creation_timeout", index="idx_events_chain_timestamp")
                except Exception as e:
                    logger.warning("index_creation_error", index="idx_events_chain_timestamp", error=str(e))
            
            logger.info("performance_indexes_check_complete")
        except Exception as e:
            # Log but don't fail - indexes might already exist or table might not exist yet
            logger.warning("index_creation_warning", error=str(e), error_type=type(e).__name__)
    
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

