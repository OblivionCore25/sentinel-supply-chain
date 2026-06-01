package com.sentinel.analysis.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.common.event.FailedEvent;
import com.sentinel.common.kafka.KafkaTopics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.listener.DefaultErrorHandler;
import org.springframework.kafka.listener.ListenerExecutionFailedException;
import org.springframework.kafka.support.serializer.DeserializationException;
import org.springframework.stereotype.Component;
import org.springframework.util.backoff.FixedBackOff;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.Instant;

/**
 * Dead letter queue handler for failed Kafka message processing.
 * <p>
 * After exhausting retries (3 attempts with 2-second intervals),
 * wraps the failed event in a {@link FailedEvent} envelope and publishes
 * it to the {@code risk.scores.dlq} topic for manual investigation.
 */
@Component
public class DeadLetterHandler {

    private static final Logger log = LoggerFactory.getLogger(DeadLetterHandler.class);

    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final ObjectMapper objectMapper;

    public DeadLetterHandler(KafkaTemplate<String, Object> kafkaTemplate,
                              ObjectMapper objectMapper) {
        this.kafkaTemplate = kafkaTemplate;
        this.objectMapper = objectMapper;
    }

    /**
     * Creates a Spring Kafka error handler configured with retry + DLQ.
     */
    public DefaultErrorHandler createErrorHandler() {
        // 3 retries at 2-second intervals
        DefaultErrorHandler handler = new DefaultErrorHandler(
                (record, exception) -> {
                    log.error("Message processing failed after retries: topic={}, key={}",
                            record.topic(), record.key(), exception);
                    sendToDlq(record.topic(), record.key() != null ? record.key().toString() : null,
                            record.value(), exception);
                },
                new FixedBackOff(2000L, 3L)
        );

        // Don't retry on deserialization errors — they'll never succeed
        handler.addNotRetryableExceptions(DeserializationException.class);

        return handler;
    }

    /**
     * Wraps a failed event and publishes it to the DLQ topic.
     */
    private void sendToDlq(String originalTopic, String key, Object failedValue, Exception exception) {
        try {
            String eventJson = failedValue != null
                    ? objectMapper.writeValueAsString(failedValue)
                    : "null";

            FailedEvent failedEvent = new FailedEvent(
                    eventJson,
                    originalTopic,
                    exception.getMessage(),
                    getStackTraceString(exception),
                    Instant.now()
            );

            kafkaTemplate.send(KafkaTopics.RISK_SCORES_DLQ, key, failedEvent);
            log.info("Failed event published to DLQ: topic={}, key={}", originalTopic, key);

        } catch (Exception dlqException) {
            log.error("Failed to publish to DLQ — event lost!", dlqException);
        }
    }

    private String getStackTraceString(Exception e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        String trace = sw.toString();
        // Truncate to 2000 chars to avoid oversized Kafka messages
        return trace.length() > 2000 ? trace.substring(0, 2000) + "..." : trace;
    }
}
