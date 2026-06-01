package com.sentinel.ingestion.publisher;

import com.sentinel.common.event.DependencyUpdateEvent;
import com.sentinel.common.event.PackageReleaseEvent;
import com.sentinel.common.event.VulnerabilityEvent;
import com.sentinel.common.kafka.KafkaTopics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Component;

import java.util.concurrent.CompletableFuture;

/**
 * Generic Kafka event publisher for the Ingestion Service.
 * Routes events to the correct topic based on event type.
 */
@Component
public class EventPublisher {

    private static final Logger log = LoggerFactory.getLogger(EventPublisher.class);

    private final KafkaTemplate<String, Object> kafkaTemplate;

    public EventPublisher(KafkaTemplate<String, Object> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    /**
     * Publishes a vulnerability disclosure event.
     * Key: CVE ID (ensures all events for the same CVE go to the same partition).
     */
    public CompletableFuture<SendResult<String, Object>> publishVulnerability(VulnerabilityEvent event) {
        log.info("Publishing vulnerability event: cveId={}, package={}, severity={}",
                event.cveId(), event.packageName(), event.severity());

        return kafkaTemplate.send(KafkaTopics.VULN_DISCLOSED, event.cveId(), event)
                .thenApply(result -> {
                    log.debug("Vulnerability event sent: topic={}, partition={}, offset={}",
                            result.getRecordMetadata().topic(),
                            result.getRecordMetadata().partition(),
                            result.getRecordMetadata().offset());
                    return result;
                })
                .exceptionally(ex -> {
                    log.error("Failed to publish vulnerability event: cveId={}", event.cveId(), ex);
                    throw new RuntimeException("Failed to publish vulnerability event", ex);
                });
    }

    /**
     * Publishes a dependency update event.
     * Key: package name (ensures ordering per package).
     */
    public CompletableFuture<SendResult<String, Object>> publishDependencyUpdate(DependencyUpdateEvent event) {
        log.info("Publishing dependency update: project={}, package={}, {} -> {}",
                event.projectId(), event.packageName(), event.previousVersion(), event.newVersion());

        return kafkaTemplate.send(KafkaTopics.DEPENDENCY_UPDATED, event.packageName(), event)
                .thenApply(result -> {
                    log.debug("Dependency update sent: topic={}, partition={}, offset={}",
                            result.getRecordMetadata().topic(),
                            result.getRecordMetadata().partition(),
                            result.getRecordMetadata().offset());
                    return result;
                })
                .exceptionally(ex -> {
                    log.error("Failed to publish dependency update: package={}", event.packageName(), ex);
                    throw new RuntimeException("Failed to publish dependency update", ex);
                });
    }

    /**
     * Publishes a package release event.
     * Key: package name.
     */
    public CompletableFuture<SendResult<String, Object>> publishPackageRelease(PackageReleaseEvent event) {
        log.info("Publishing package release: package={}, version={}, ecosystem={}",
                event.packageName(), event.version(), event.ecosystem());

        return kafkaTemplate.send(KafkaTopics.PACKAGE_RELEASED, event.packageName(), event)
                .thenApply(result -> {
                    log.debug("Package release sent: topic={}, partition={}, offset={}",
                            result.getRecordMetadata().topic(),
                            result.getRecordMetadata().partition(),
                            result.getRecordMetadata().offset());
                    return result;
                })
                .exceptionally(ex -> {
                    log.error("Failed to publish package release: package={}", event.packageName(), ex);
                    throw new RuntimeException("Failed to publish package release", ex);
                });
    }
}
