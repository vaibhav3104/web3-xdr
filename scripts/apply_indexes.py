"""
Apply performance indexes to the events table.
Run this script after upgrading the database instance to g1-small.
"""

import asyncio
import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

# Force asyncpg driver
DB_URL = os.getenv("DATABASE_URL", "")
if not DB_URL:
    raise ValueError("DATABASE_URL environment variable is not set")

# Convert postgresql:// to postgresql+asyncpg:// for asyncpg driver
if DB_URL.startswith("postgresql://"):
    DB_URL = DB_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
elif DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql+asyncpg://", 1)

async def apply_indexes():
    """Apply performance indexes to optimize query performance."""
    print(f"🔌 Connecting to {DB_URL.split('@')[-1]}...")
    engine = create_async_engine(DB_URL)
    
    try:
        async with engine.begin() as conn:
            print("🚀 Applying Indexes...")
            
            # Index 1: For Timeline Sorting (Essential for API)
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC);"
            ))
            print("✅ Created idx_events_created_at")

            # Index 2: For Chain Filtering + Time (Essential for Dashboard)
            await conn.execute(text(
                "CREATE INDEX IF NOT EXISTS idx_events_chain_timestamp ON events(chain_id, block_timestamp DESC);"
            ))
            print("✅ Created idx_events_chain_timestamp")
            
        print("✨ All indexes applied successfully.")
    except Exception as e:
        print(f"❌ Error applying indexes: {e}")
        raise
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(apply_indexes())
