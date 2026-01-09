-- Migration: Add Status Column and Other Missing Fields to Events Table
-- Run this on Cloud SQL to fix the schema mismatch

-- Add status column (if not exists)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'events' AND column_name = 'status'
    ) THEN
        ALTER TABLE events ADD COLUMN status VARCHAR(16) NOT NULL DEFAULT 'PENDING';
        CREATE INDEX IF NOT EXISTS ix_events_status ON events(status, chain_id);
    END IF;
END $$;

-- Add block_hash column (if not exists)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'events' AND column_name = 'block_hash'
    ) THEN
        ALTER TABLE events ADD COLUMN block_hash VARCHAR(128);
        CREATE INDEX IF NOT EXISTS ix_events_block_hash ON events(block_hash);
    END IF;
END $$;

-- Add canonical_event_hash column (if not exists)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'events' AND column_name = 'canonical_event_hash'
    ) THEN
        ALTER TABLE events ADD COLUMN canonical_event_hash VARCHAR(128);
        CREATE INDEX IF NOT EXISTS ix_events_canonical_event_hash ON events(canonical_event_hash);
    END IF;
END $$;

-- Add confirmed_at column (if not exists)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'events' AND column_name = 'confirmed_at'
    ) THEN
        ALTER TABLE events ADD COLUMN confirmed_at TIMESTAMP WITH TIME ZONE;
    END IF;
END $$;

-- Add log_index column (if not exists)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'events' AND column_name = 'log_index'
    ) THEN
        ALTER TABLE events ADD COLUMN log_index INTEGER;
    END IF;
END $$;

-- Add topics column (if not exists)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'events' AND column_name = 'topics'
    ) THEN
        ALTER TABLE events ADD COLUMN topics VARCHAR(128)[];
    END IF;
END $$;

-- Add asset_type column (if not exists)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'events' AND column_name = 'asset_type'
    ) THEN
        ALTER TABLE events ADD COLUMN asset_type VARCHAR(32);
    END IF;
END $$;

-- Add asset_address column (if not exists)
DO $$ 
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'events' AND column_name = 'asset_address'
    ) THEN
        ALTER TABLE events ADD COLUMN asset_address VARCHAR(128);
    END IF;
END $$;

-- Add unique constraint for deduplication (if not exists)
CREATE UNIQUE INDEX IF NOT EXISTS ix_events_unique_key ON events(chain_id, tx_hash, log_index);

-- Verify migration
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_name = 'events'
ORDER BY ordinal_position;
