-- Create event_processing table for idempotency
-- Run this migration ASAP to fix event ingestion

CREATE TABLE IF NOT EXISTS event_processing (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    idempotency_key VARCHAR(128) UNIQUE NOT NULL,
    first_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    event_id VARCHAR(128),
    incident_id VARCHAR(128),
    error_message TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_event_processing_status ON event_processing(status, first_seen_at);
CREATE INDEX IF NOT EXISTS ix_event_processing_processed ON event_processing(processed_at);
CREATE INDEX IF NOT EXISTS ix_event_processing_idempotency_key ON event_processing(idempotency_key);

-- Verify table was created
SELECT 
    table_name, 
    column_name, 
    data_type 
FROM information_schema.columns 
WHERE table_name = 'event_processing'
ORDER BY ordinal_position;
