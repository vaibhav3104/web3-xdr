"""
Check database status: events count and indexes.
This script can be run via Cloud Run or locally with DATABASE_URL set.
"""

import asyncio
import os
import sys
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text

# Get database URL
DB_URL = os.getenv("DATABASE_URL", "")
if not DB_URL:
    print("❌ DATABASE_URL not set")
    sys.exit(1)

# Convert to asyncpg driver
if DB_URL.startswith("postgresql://"):
    DB_URL = DB_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
elif DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql+asyncpg://", 1)

async def check_database():
    """Check database status."""
    print(f"🔌 Connecting to database...")
    engine = create_async_engine(DB_URL, pool_pre_ping=True)
    
    try:
        async with engine.connect() as conn:
            # Check events count
            print("\n📊 Checking Events Count...")
            result = await conn.execute(text("SELECT COUNT(*) as count FROM events"))
            count = result.scalar()
            print(f"   Total events in database: {count}")
            
            # Check recent events
            result = await conn.execute(text("""
                SELECT chain_id, event_type, COUNT(*) as cnt 
                FROM events 
                GROUP BY chain_id, event_type 
                ORDER BY cnt DESC 
                LIMIT 10
            """))
            rows = result.fetchall()
            if rows:
                print("\n   Top event types:")
                for row in rows:
                    print(f"     {row[0]} | {row[1]} | {row[2]} events")
            else:
                print("   No events found")
            
            # Check indexes
            print("\n🔍 Checking Indexes...")
            result = await conn.execute(text("""
                SELECT indexname, indexdef 
                FROM pg_indexes 
                WHERE tablename = 'events' 
                ORDER BY indexname
            """))
            indexes = result.fetchall()
            if indexes:
                print(f"   Found {len(indexes)} indexes on events table:")
                for idx in indexes:
                    print(f"     ✅ {idx[0]}")
                    if 'idx_events_created_at' in idx[0] or 'idx_events_chain_timestamp' in idx[0]:
                        print(f"        {idx[1][:80]}...")
            else:
                print("   ⚠️  No indexes found on events table")
            
            # Check for our specific indexes
            print("\n🎯 Checking Performance Indexes...")
            result = await conn.execute(text("""
                SELECT indexname 
                FROM pg_indexes 
                WHERE tablename = 'events' 
                AND (indexname LIKE 'idx_events_created_at' OR indexname LIKE 'idx_events_chain_timestamp')
            """))
            perf_indexes = result.fetchall()
            expected = ['idx_events_created_at', 'idx_events_chain_timestamp']
            found = [idx[0] for idx in perf_indexes]
            for exp in expected:
                if exp in found:
                    print(f"   ✅ {exp} exists")
                else:
                    print(f"   ❌ {exp} MISSING")
            
            # Check table stats
            print("\n📈 Table Statistics...")
            result = await conn.execute(text("""
                SELECT 
                    COUNT(*) as total,
                    COUNT(DISTINCT chain_id) as chains,
                    MIN(created_at) as oldest,
                    MAX(created_at) as newest
                FROM events
            """))
            stats = result.fetchone()
            if stats and stats[0] > 0:
                print(f"   Total events: {stats[0]}")
                print(f"   Chains: {stats[1]}")
                print(f"   Oldest: {stats[2]}")
                print(f"   Newest: {stats[3]}")
            else:
                print("   No events in table")
                
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(check_database())
