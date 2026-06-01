package com.sentinel.common.event;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.sentinel.common.model.Ecosystem;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

/**
 * Represents a dependency version change in a monitored project.
 * Published to the {@code dependency.updated} Kafka topic, keyed by package name.
 *
 * @param projectId       ID of the monitored project
 * @param packageName     the dependency that was updated
 * @param previousVersion version before the update (nullable for new additions)
 * @param newVersion      version after the update
 * @param ecosystem       package ecosystem (MAVEN or NPM)
 * @param timestamp       when this update was detected
 */
public record DependencyUpdateEvent(
        @NotBlank String projectId,
        @NotBlank String packageName,
        String previousVersion,
        @NotBlank String newVersion,
        @NotNull Ecosystem ecosystem,
        @JsonFormat(shape = JsonFormat.Shape.STRING) Instant timestamp
) {
    public DependencyUpdateEvent {
        if (timestamp == null) {
            timestamp = Instant.now();
        }
    }
}
