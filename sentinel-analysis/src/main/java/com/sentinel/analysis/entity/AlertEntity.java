package com.sentinel.analysis.entity;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * JPA entity for active alerts triggered when risk scores exceed thresholds.
 */
@Entity
@Table(name = "alerts")
public class AlertEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "project_id", nullable = false)
    private UUID projectId;

    @Column(name = "vulnerability_id")
    private UUID vulnerabilityId;

    @Column(name = "cve_id", nullable = false)
    private String cveId;

    @Column(name = "package_name", nullable = false)
    private String packageName;

    @Column(nullable = false)
    private String severity;

    @Column(columnDefinition = "TEXT")
    private String message;

    @Column(name = "risk_score")
    private BigDecimal riskScore;

    @Column
    private boolean acknowledged = false;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "acknowledged_at")
    private Instant acknowledgedAt;

    public AlertEntity() {}

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = Instant.now();
    }

    public void acknowledge() {
        this.acknowledged = true;
        this.acknowledgedAt = Instant.now();
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

    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }

    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }

    public BigDecimal getRiskScore() { return riskScore; }
    public void setRiskScore(BigDecimal riskScore) { this.riskScore = riskScore; }

    public boolean isAcknowledged() { return acknowledged; }

    public Instant getCreatedAt() { return createdAt; }
    public Instant getAcknowledgedAt() { return acknowledgedAt; }
}
