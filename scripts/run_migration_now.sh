#!/bin/bash
# Quick migration script to add status column to events table
# This can be run via Cloud SQL proxy or directly if you have access

echo "🔧 Running Database Migration..."
echo ""

# Read the SQL migration file and execute it
# Note: This requires Cloud SQL proxy or direct access to the database

cat << 'SQL' | psql "$DATABASE_URL" 2>&1 || echo "⚠️  If psql fails, use Cloud SQL proxy or run via API endpoint"

-- Add status column
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'events' AND column_name = 'status'
    ) THEN
        ALTER TABLE events ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'PENDING';
        CREATE INDEX IF NOT EXISTS ix_events_status ON events(status, chain_id);
        RAISE NOTICE 'Added status column';
    ELSE
        RAISE NOTICE 'status column already exists';
    END IF;
END $$;

-- Add other missing columns
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'block_hash') THEN
        ALTER TABLE events ADD COLUMN block_hash VARCHAR(128);
        CREATE INDEX IF NOT EXISTS ix_events_block_hash ON events(block_hash);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'canonical_event_hash') THEN
        ALTER TABLE events ADD COLUMN canonical_event_hash VARCHAR(128);
        CREATE INDEX IF NOT EXISTS ix_events_canonical_event_hash ON events(canonical_event_hash);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'confirmed_at') THEN
        ALTER TABLE events ADD COLUMN confirmed_at TIMESTAMP WITH TIME ZONE;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'log_index') THEN
        ALTER TABLE events ADD COLUMN log_index INTEGER;
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'topics') THEN
        ALTER TABLE events ADD COLUMN topics VARCHAR(128)[];
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'asset_type') THEN
        ALTER TABLE events ADD COLUMN asset_type VARCHAR(32);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'events' AND column_name = 'asset_address') THEN
        ALTER TABLE events ADD COLUMN asset_address VARCHAR(128);
    END IF;
END $$;

-- Add unique constraint
CREATE UNIQUE INDEX IF NOT EXISTS ix_events_unique_key ON events(chain_id, tx_hash, log_index);

SELECT 'Migration completed successfully!' as result;

SQL

echo ""
echo "✅ Migration script executed"
