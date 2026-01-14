"""
Check the actual database table schema.
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

if DB_URL.startswith("postgresql://"):
    DB_URL = DB_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
elif DB_URL.startswith("postgres://"):
    DB_URL = DB_URL.replace("postgres://", "postgresql+asyncpg://", 1)

async def check_schema():
    """Check actual table schema."""
    print("🔌 Connecting to database...")
    engine = create_async_engine(DB_URL, pool_pre_ping=True)
    
    try:
        async with engine.connect() as conn:
            # Get column information
            print("\n📊 Checking events table schema...")
            result = await conn.execute(text("""
                SELECT 
                    column_name, 
                    data_type, 
                    is_nullable,
                    column_default
                FROM information_schema.columns 
                WHERE table_name = 'events' 
                ORDER BY ordinal_position
            """))
            columns = result.fetchall()
            
            if columns:
                print(f"\n✅ Found {len(columns)} columns in events table:\n")
                for col in columns:
                    nullable = "NULL" if col[2] == "YES" else "NOT NULL"
                    default = f" DEFAULT {col[3]}" if col[3] else ""
                    print(f"  - {col[0]:30} {col[1]:20} {nullable}{default}")
            else:
                print("❌ Table 'events' does not exist!")
            
            # Check constraints
            print("\n🔍 Checking constraints...")
            result = await conn.execute(text("""
                SELECT 
                    conname as constraint_name,
                    contype as constraint_type,
                    pg_get_constraintdef(oid) as definition
                FROM pg_constraint
                WHERE conrelid = 'events'::regclass
            """))
            constraints = result.fetchall()
            
            if constraints:
                print(f"\n✅ Found {len(constraints)} constraints:\n")
                for con in constraints:
                    print(f"  - {con[0]} ({con[1]}): {con[2]}")
            else:
                print("  No constraints found")
                
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        await engine.dispose()

if __name__ == "__main__":
    asyncio.run(check_schema())
