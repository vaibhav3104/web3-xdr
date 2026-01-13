#!/usr/bin/env python3
"""
One-time Cloud Run Job to create performance indexes.
Run this as a Cloud Run job to apply indexes without blocking the API.
"""

import asyncio
import os
import sys
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

DB_URL = os.getenv("DATABASE_URL", "")
if not DB_URL:
    print("❌ DATABASE_URL not set")
    sys.exit(1)

# Convert to asyncpg
if DB_URL.startswith("postgresql://"):
    DB_URL = DB_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
elif DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql+asyncpg://", 1)

async def create_indexes():
    """Create performance indexes."""
    print("🔌 Connecting to database...")
    engine = create_async_engine(
        DB_URL,
        pool_size=2,
        pool_pre_ping=True,
        connect_args={
            "server_settings": {
                "statement_timeout": "60000",  # 60 seconds for index creation
            },
            "command_timeout": 60,
        }
    )
    
    try:
        async with engine.begin() as conn:
            print("🚀 Creating indexes (this may take a minute)...")
            
            # Index 1: Timeline sorting
            try:
                await conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC);"
                ))
                print("✅ Created idx_events_created_at")
            except Exception as e:
                print(f"⚠️  Error creating idx_events_created_at: {e}")
            
            # Index 2: Chain + timestamp
            try:
                await conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS idx_events_chain_timestamp ON events(chain_id, block_timestamp DESC);"
                ))
                print("✅ Created idx_events_chain_timestamp")
            except Exception as e:
                print(f"⚠️  Error creating idx_events_chain_timestamp: {e}")
            
            # Index 3: Chain + event_type (for filtering)
            try:
                await conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS idx_events_chain_type ON events(chain_id, event_type);"
                ))
                print("✅ Created idx_events_chain_type")
            except Exception as e:
                print(f"⚠️  Error creating idx_events_chain_type: {e}")
            
        print("✨ Index creation complete!")
        
        # Verify indexes
        async with engine.connect() as conn:
            result = await conn.execute(text("""
                SELECT indexname FROM pg_indexes 
                WHERE tablename = 'events' 
                AND indexname LIKE 'idx_events%'
                ORDER BY indexname
            """))
            indexes = [row[0] for row in result.fetchall()]
            print(f"\n📊 Found {len(indexes)} performance indexes:")
            for idx in indexes:
                print(f"   ✅ {idx}")
                
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(create_indexes())
