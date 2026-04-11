-- Sentinel3: Incident Audit Log Migration
-- Tracks every status change for SOC compliance

CREATE TABLE IF NOT EXISTS incident_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id VARCHAR(128) NOT NULL,
    action VARCHAR(32) NOT NULL,
    previous_status VARCHAR(32),
    new_status VARCHAR(32) NOT NULL,
    analyst_id VARCHAR(256),
    notes TEXT,
    metadata_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_audit_incident_time ON incident_audit_log (incident_id, created_at);
CREATE INDEX IF NOT EXISTS ix_audit_action ON incident_audit_log (action, created_at);
