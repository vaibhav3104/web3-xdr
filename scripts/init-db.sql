-- ============================================================================
-- Web3 XDR - PostgreSQL Initialization Script
-- ============================================================================
-- This script runs automatically when the PostgreSQL container starts for the
-- first time. It sets up extensions and creates the initial schema.
-- ============================================================================

-- Enable useful extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For text search

-- Create read-only user for dashboards (optional)
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'xdr_readonly') THEN
        CREATE ROLE xdr_readonly WITH LOGIN PASSWORD 'readonly_password';
    END IF;
END
$$;

-- Grant permissions to readonly user (run after tables are created)
-- GRANT USAGE ON SCHEMA public TO xdr_readonly;
-- GRANT SELECT ON ALL TABLES IN SCHEMA public TO xdr_readonly;

-- ============================================================================
-- Note: The actual tables are created by SQLAlchemy's create_all() method
-- when the application starts. This script only sets up prerequisites.
-- ============================================================================

-- Create indexes for common queries (these will be created by SQLAlchemy too,
-- but we define them here for reference)

-- Events table indexes (created by model)
-- CREATE INDEX IF NOT EXISTS ix_events_chain_block ON events(chain_id, block_number);
-- CREATE INDEX IF NOT EXISTS ix_events_chain_timestamp ON events(chain_id, block_timestamp);
-- CREATE INDEX IF NOT EXISTS ix_events_contract_type ON events(contract_address, event_type);

-- Incidents table indexes
-- CREATE INDEX IF NOT EXISTS ix_incidents_severity_status ON incidents(severity, status);
-- CREATE INDEX IF NOT EXISTS ix_incidents_created_at ON incidents(created_at);

-- ============================================================================
-- Maintenance functions
-- ============================================================================

-- Function to clean up old events (called by scheduled job)
CREATE OR REPLACE FUNCTION cleanup_old_events(days_to_keep INTEGER DEFAULT 30)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM events 
    WHERE created_at < NOW() - (days_to_keep || ' days')::INTERVAL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    RAISE NOTICE 'Deleted % old events', deleted_count;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get event statistics for a time range
CREATE OR REPLACE FUNCTION get_event_stats(
    start_time TIMESTAMP WITH TIME ZONE DEFAULT NOW() - INTERVAL '24 hours',
    end_time TIMESTAMP WITH TIME ZONE DEFAULT NOW()
)
RETURNS TABLE (
    chain_id VARCHAR,
    event_type VARCHAR,
    event_count BIGINT,
    total_volume_usd NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        e.chain_id,
        e.event_type,
        COUNT(*)::BIGINT as event_count,
        COALESCE(SUM(e.amount_usd), 0) as total_volume_usd
    FROM events e
    WHERE e.block_timestamp BETWEEN start_time AND end_time
    GROUP BY e.chain_id, e.event_type
    ORDER BY event_count DESC;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Sample scheduled cleanup (requires pg_cron extension, typically set up 
-- externally or via cloud provider)
-- ============================================================================
-- SELECT cron.schedule('cleanup-old-events', '0 3 * * *', 'SELECT cleanup_old_events(30)');

COMMENT ON DATABASE web3_xdr IS 'Web3 XDR - Cross-Chain Security Monitoring System';

