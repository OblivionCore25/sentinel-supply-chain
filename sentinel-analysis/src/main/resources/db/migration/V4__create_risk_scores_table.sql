-- Risk score history (for trend visualization)
CREATE TABLE risk_scores (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id       UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    vulnerability_id UUID REFERENCES vulnerabilities(id) ON DELETE SET NULL,
    cve_id           VARCHAR(50) NOT NULL,
    score            DECIMAL(4,2) NOT NULL,
    transitive_depth INTEGER,
    path_count       INTEGER,
    scored_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_risk_scores_project_time ON risk_scores(project_id, scored_at DESC);
CREATE INDEX idx_risk_scores_cve ON risk_scores(cve_id);
