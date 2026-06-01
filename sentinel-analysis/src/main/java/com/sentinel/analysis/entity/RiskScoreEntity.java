package com.sentinel.analysis.entity;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * JPA entity for computed risk scores (historical, for trend visualization).
 */
@Entity
@Table(name = "risk_scores")
public class RiskScoreEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "project_id", nullable = false)
    private UUID projectId;

    @Column(name = "vulnerability_id")
    private UUID vulnerabilityId;

    @Column(name = "cve_id", nullable = false)
    private String cveId;

    @Column(nullable = false)
    private BigDecimal score;

    @Column(name = "transitive_depth")
    private Integer transitiveDepth;

    @Column(name = "path_count")
    private Integer pathCount;

    @Column(name = "scored_at")
    private Instant scoredAt;

    public RiskScoreEntity() {}

    @PrePersist
    protected void onCreate() {
        if (scoredAt == null) scoredAt = Instant.now();
    }

    // --- Getters and Setters ---

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public UUID getProjectId() { return projectId; }
    public void setProjectId(UUID projectId) { this.projectId = projectId; }

    public UUID getVulnerabilityId() { return vulnerabilityId; }
    public void setVulnerabilityId(UUID vulnerabilityId) { this.vulnerabilityId = vulnerabilityId; }

    public String getCveId() { return cveId; }
    public void setCveId(String cveId) { this.cveId = cveId; }

    public BigDecimal getScore() { return score; }
    public void setScore(BigDecimal score) { this.score = score; }

    public Integer getTransitiveDepth() { return transitiveDepth; }
    public void setTransitiveDepth(Integer transitiveDepth) { this.transitiveDepth = transitiveDepth; }

    public Integer getPathCount() { return pathCount; }
    public void setPathCount(Integer pathCount) { this.pathCount = pathCount; }

    public Instant getScoredAt() { return scoredAt; }
}
