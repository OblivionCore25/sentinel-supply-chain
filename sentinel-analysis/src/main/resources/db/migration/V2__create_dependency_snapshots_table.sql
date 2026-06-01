-- Dependency snapshots (rebuilt on each dependency.updated event)
CREATE TABLE dependency_snapshots (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    resolved_at     TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    dependency_tree JSONB NOT NULL            -- Full resolved dependency tree
);

CREATE INDEX idx_dep_snapshots_project ON dependency_snapshots(project_id, resolved_at DESC);
