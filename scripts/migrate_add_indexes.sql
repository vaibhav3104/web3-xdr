-- Production Hardening: Additional Database Indexes
-- Run this migration to add performance indexes for common queries

-- Cursor pagination index (already added to model, but ensure it exists)
CREATE INDEX IF NOT EXISTS ix_events_timestamp_id ON events(block_timestamp DESC, id DESC);

-- Chain + timestamp (for chain-specific queries)
CREATE INDEX IF NOT EXISTS ix_events_chain_timestamp_desc ON events(chain_id, block_timestamp DESC);

-- Severity + timestamp (for severity filtering)
CREATE INDEX IF NOT EXISTS ix_events_severity_timestamp_desc ON events(severity, block_timestamp DESC);

-- Event type + timestamp (for event type filtering)
CREATE INDEX IF NOT EXISTS ix_events_type_timestamp_desc ON events(event_type, block_timestamp DESC);

-- Status + block number (for finality tracking)
CREATE INDEX IF NOT EXISTS ix_events_status_block ON events(status, block_number);

-- Contract address + timestamp (for contract-specific queries)
CREATE INDEX IF NOT EXISTS ix_events_contract_timestamp_desc ON events(contract_address, block_timestamp DESC);

-- Composite index for common filter combinations
CREATE INDEX IF NOT EXISTS ix_events_chain_severity_timestamp ON events(chain_id, severity, block_timestamp DESC);

-- Verify indexes were created
SELECT 
    schemaname,
    tablename,
    indexname,
    indexdef
FROM pg_indexes
WHERE tablename = 'events'
ORDER BY indexname;
