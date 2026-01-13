-- Performance indexes for events table
-- Run after upgrading to db-g1-small

-- Index 1: For Timeline Sorting (Essential for API)
CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at DESC);

-- Index 2: For Chain Filtering + Time (Essential for Dashboard)
CREATE INDEX IF NOT EXISTS idx_events_chain_timestamp ON events(chain_id, block_timestamp DESC);
