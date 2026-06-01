-- Known vulnerabilities from external feeds
CREATE TABLE vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id          VARCHAR(50) UNIQUE NOT NULL,
    package_name    VARCHAR(255) NOT NULL,
    affected_range  VARCHAR(255),              -- e.g., '>=2.0.0, <2.17.1'
    cvss_score      DECIMAL(3,1),
    severity        VARCHAR(20),               -- CRITICAL, HIGH, MEDIUM, LOW
    description     TEXT,
    published_at    TIMESTAMP WITH TIME ZONE,
    source          VARCHAR(50),               -- 'NVD', 'OSV', 'GITHUB'
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_vuln_package ON vulnerabilities(package_name);
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
