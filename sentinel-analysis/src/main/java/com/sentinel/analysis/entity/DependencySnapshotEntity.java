package com.sentinel.analysis.entity;

import jakarta.persistence.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.UUID;

/**
 * JPA entity for dependency tree snapshots.
 * Each snapshot stores a full resolved dependency tree as JSONB.
 */
@Entity
@Table(name = "dependency_snapshots")
public class DependencySnapshotEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "project_id", nullable = false)
    private UUID projectId;

    @Column(name = "resolved_at")
    private Instant resolvedAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "dependency_tree", nullable = false, columnDefinition = "jsonb")
    private String dependencyTree;

    public DependencySnapshotEntity() {}

    public DependencySnapshotEntity(UUID projectId, String dependencyTree) {
        this.projectId = projectId;
        this.dependencyTree = dependencyTree;
        this.resolvedAt = Instant.now();
    }

    @PrePersist
    protected void onCreate() {
        if (resolvedAt == null) resolvedAt = Instant.now();
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public UUID getProjectId() { return projectId; }
    public void setProjectId(UUID projectId) { this.projectId = projectId; }

    public Instant getResolvedAt() { return resolvedAt; }

    public String getDependencyTree() { return dependencyTree; }
    public void setDependencyTree(String dependencyTree) { this.dependencyTree = dependencyTree; }
}
