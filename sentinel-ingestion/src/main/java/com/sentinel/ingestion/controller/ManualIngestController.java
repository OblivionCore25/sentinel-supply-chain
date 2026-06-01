package com.sentinel.ingestion.controller;

import com.sentinel.common.event.DependencyUpdateEvent;
import com.sentinel.common.event.VulnerabilityEvent;
import com.sentinel.common.model.Ecosystem;
import com.sentinel.common.model.EventSource;
import com.sentinel.common.model.Severity;
import com.sentinel.ingestion.dedup.EventDeduplicator;
import com.sentinel.ingestion.publisher.EventPublisher;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

/**
 * Manual event injection endpoints for development, demos, and testing.
 * These endpoints accept simplified payloads and publish to Kafka directly.
 */
@RestController
@RequestMapping("/api/ingest")
public class ManualIngestController {

    private static final Logger log = LoggerFactory.getLogger(ManualIngestController.class);

    private final EventPublisher eventPublisher;
    private final EventDeduplicator deduplicator;

    public ManualIngestController(EventPublisher eventPublisher, EventDeduplicator deduplicator) {
        this.eventPublisher = eventPublisher;
        this.deduplicator = deduplicator;
    }

    /**
     * Manually inject a vulnerability event.
     *
     * <pre>
     * POST /api/ingest/vulnerability
     * {
     *   "cveId": "CVE-2026-99999",
     *   "packageName": "com.example:vulnerable-lib",
     *   "affectedRange": ">=1.0.0, <1.5.3",
     *   "cvssScore": 9.8,
     *   "severity": "CRITICAL",
     *   "description": "Remote code execution via crafted input"
     * }
     * </pre>
     */
    @PostMapping("/vulnerability")
    public ResponseEntity<Map<String, Object>> ingestVulnerability(
            @Valid @RequestBody VulnerabilityRequest request) {

        log.info("Manual vulnerability ingest: cveId={}, package={}",
                request.cveId(), request.packageName());

        Severity severity = request.severity() != null
                ? request.severity()
                : Severity.fromCvss(request.cvssScore());

        VulnerabilityEvent event = new VulnerabilityEvent(
                request.cveId(),
                request.packageName(),
                request.affectedRange(),
                request.cvssScore(),
                severity,
                request.description(),
                EventSource.MANUAL,
                Instant.now(),
                Instant.now()
        );

        // Skip dedup for manual ingest (allow re-injection for testing)
        eventPublisher.publishVulnerability(event);

        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(Map.of(
                        "status", "accepted",
                        "cveId", event.cveId(),
                        "topic", "vuln.disclosed"
                ));
    }

    /**
     * Manually inject a dependency update event.
     *
     * <pre>
     * POST /api/ingest/dependency-update
     * {
     *   "projectId": "my-api-service",
     *   "packageName": "com.example:vulnerable-lib",
     *   "previousVersion": "1.4.0",
     *   "newVersion": "1.5.3",
     *   "ecosystem": "MAVEN"
     * }
     * </pre>
     */
    @PostMapping("/dependency-update")
    public ResponseEntity<Map<String, Object>> ingestDependencyUpdate(
            @Valid @RequestBody DependencyUpdateRequest request) {

        log.info("Manual dependency update ingest: project={}, package={}, {} -> {}",
                request.projectId(), request.packageName(),
                request.previousVersion(), request.newVersion());

        Ecosystem ecosystem = request.ecosystem() != null
                ? request.ecosystem()
                : Ecosystem.MAVEN;

        DependencyUpdateEvent event = new DependencyUpdateEvent(
                request.projectId(),
                request.packageName(),
                request.previousVersion(),
                request.newVersion(),
                ecosystem,
                Instant.now()
        );

        eventPublisher.publishDependencyUpdate(event);

        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(Map.of(
                        "status", "accepted",
                        "projectId", event.projectId(),
                        "topic", "dependency.updated"
                ));
    }

    // --- Request DTOs ---

    public record VulnerabilityRequest(
            @NotBlank String cveId,
            @NotBlank String packageName,
            String affectedRange,
            double cvssScore,
            Severity severity,
            String description
    ) {}

    public record DependencyUpdateRequest(
            @NotBlank String projectId,
            @NotBlank String packageName,
            String previousVersion,
            @NotBlank String newVersion,
            Ecosystem ecosystem
    ) {}
}
