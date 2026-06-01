package com.sentinel.common.event;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.sentinel.common.model.Ecosystem;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.time.Instant;

/**
 * Represents a new package version release on a registry.
 * Published to the {@code package.released} Kafka topic, keyed by package name.
 *
 * @param packageName  the package that was released
 * @param version      newly released version
 * @param ecosystem    package ecosystem (MAVEN or NPM)
 * @param timestamp    when this release was detected
 */
public record PackageReleaseEvent(
        @NotBlank String packageName,
        @NotBlank String version,
        @NotNull Ecosystem ecosystem,
        @JsonFormat(shape = JsonFormat.Shape.STRING) Instant timestamp
) {
    public PackageReleaseEvent {
        if (timestamp == null) {
            timestamp = Instant.now();
        }
    }
}
