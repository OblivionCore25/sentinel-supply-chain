package com.sentinel.analysis.entity;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

/**
 * JPA entity for monitored software projects.
 */
@Entity
@Table(name = "projects")
public class ProjectEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(name = "repository_url")
    private String repositoryUrl;

    @Column(nullable = false)
    private String ecosystem;

    @Column(name = "manifest_path")
    private String manifestPath;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    public ProjectEntity() {}

    public ProjectEntity(String name, String ecosystem) {
        this.name = name;
        this.ecosystem = ecosystem;
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = Instant.now();
        if (updatedAt == null) updatedAt = Instant.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }

    // --- Getters and Setters ---

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getRepositoryUrl() { return repositoryUrl; }
    public void setRepositoryUrl(String repositoryUrl) { this.repositoryUrl = repositoryUrl; }

    public String getEcosystem() { return ecosystem; }
    public void setEcosystem(String ecosystem) { this.ecosystem = ecosystem; }

    public String getManifestPath() { return manifestPath; }
    public void setManifestPath(String manifestPath) { this.manifestPath = manifestPath; }

    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
