package com.sentinel.common.event;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.sentinel.common.model.Severity;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

/**
 * High-severity alert generated when a risk score exceeds the configured threshold.
 * Published to the {@code risk.alerts} Kafka topic, keyed by project ID.
 *
 * @param projectId   monitored project ID
 * @param projectName human-readable project name
 * @param cveId       CVE identifier
 * @param packageName affected package
 * @param severity    alert severity
 * @param message     human-readable alert message
 * @param riskScore   the computed risk score that triggered this alert
 * @param timestamp   when this alert was created
 */
public record AlertEvent(
        @NotBlank String projectId,
        String projectName,
        @NotBlank String cveId,
        @NotBlank String packageName,
        @NotNull Severity severity,
        String message,
        double riskScore,
        @JsonFormat(shape = JsonFormat.Shape.STRING) Instant timestamp
) {
    public AlertEvent {
        if (timestamp == null) {
            timestamp = Instant.now();
        }
    }
}
