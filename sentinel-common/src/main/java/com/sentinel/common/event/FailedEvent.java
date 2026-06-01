package com.sentinel.common.event;

import com.fasterxml.jackson.annotation.JsonFormat;

import java.time.Instant;

/**
 * Envelope for events that failed processing, routed to the dead letter queue.
 * Published to the {@code risk.scores.dlq} Kafka topic.
 *
 * @param originalEventJson  serialized JSON of the original event that failed
 * @param originalTopic      the Kafka topic the original event came from
 * @param errorMessage       human-readable error description
 * @param stackTrace         full stack trace of the failure
 * @param failedAt           when the failure occurred
 */
public record FailedEvent(
        String originalEventJson,
        String originalTopic,
        String errorMessage,
        String stackTrace,
        @JsonFormat(shape = JsonFormat.Shape.STRING) Instant failedAt
) {
    public FailedEvent {
        if (failedAt == null) {
            failedAt = Instant.now();
        }
    }
}
