package com.sentinel.common.event;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.validation.constraints.NotBlank;

import java.time.Instant;
import java.util.List;

/**
 * Computed risk score for a specific project–vulnerability pair.
 * Published to the {@code risk.scores} Kafka topic, keyed by project ID.
 *
 * @param projectId              monitored project ID
 * @param projectName            human-readable project name
 * @param vulnerabilityId        internal vulnerability record ID
 * @param cveId                  CVE identifier
 * @param score                  computed risk score (0.0 - 10.0+)
 * @param transitiveDepth        shortest path depth to the vulnerable package
 * @param pathCount              number of distinct transitive paths
 * @param affectedDependencies   list of package identifiers on the affected paths
 * @param scoredAt               when this score was computed
 */
public record RiskScoreEvent(
        @NotBlank String projectId,
        String projectName,
        String vulnerabilityId,
        @NotBlank String cveId,
        double score,
        int transitiveDepth,
        int pathCount,
        List<String> affectedDependencies,
        @JsonFormat(shape = JsonFormat.Shape.STRING) Instant scoredAt
) {
    public RiskScoreEvent {
        if (scoredAt == null) {
            scoredAt = Instant.now();
        }
        if (affectedDependencies == null) {
            affectedDependencies = List.of();
        }
    }
}
