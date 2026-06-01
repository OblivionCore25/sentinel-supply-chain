-- Active alerts
CREATE TABLE alerts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id       UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    cve_id           VARCHAR(50) NOT NULL,
    package_name     VARCHAR(255) NOT NULL,
    severity         VARCHAR(20) NOT NULL,
    message          TEXT,
    risk_score       DECIMAL(4,2),
    acknowledged     BOOLEAN DEFAULT FALSE,
    created_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    acknowledged_at  TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_alerts_project ON alerts(project_id, created_at DESC);
CREATE INDEX idx_alerts_unacked ON alerts(project_id) WHERE acknowledged = FALSE;
