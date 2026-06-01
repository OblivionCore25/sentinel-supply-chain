-- Monitored projects
CREATE TABLE projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL UNIQUE,
    repository_url  VARCHAR(512),
    ecosystem       VARCHAR(50) NOT NULL,     -- 'MAVEN', 'NPM'
    manifest_path   VARCHAR(512),             -- 'pom.xml', 'package.json'
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX idx_projects_ecosystem ON projects(ecosystem);
