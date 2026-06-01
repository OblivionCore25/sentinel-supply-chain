package com.sentinel.ingestion.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.common.event.PackageReleaseEvent;
import com.sentinel.common.model.Ecosystem;
import com.sentinel.ingestion.publisher.EventPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.Map;

/**
 * Receives npm registry change notifications.
 * <p>
 * npm can be configured to send webhook notifications when packages are published.
 * This controller normalizes those payloads into {@link PackageReleaseEvent} records.
 */
@RestController
@RequestMapping("/webhooks/npm")
public class NpmWebhookController {

    private static final Logger log = LoggerFactory.getLogger(NpmWebhookController.class);

    private final EventPublisher publisher;
    private final ObjectMapper objectMapper;

    public NpmWebhookController(EventPublisher publisher, ObjectMapper objectMapper) {
        this.publisher = publisher;
        this.objectMapper = objectMapper;
    }

    /**
     * Handles npm package publish/update webhook events.
     * <p>
     * Expected payload structure:
     * <pre>
     * {
     *   "event": "package:publish",
     *   "name": "lodash",
     *   "version": "4.17.22",
     *   "time": "2026-01-15T..."
     * }
     * </pre>
     */
    @PostMapping
    public ResponseEntity<Map<String, Object>> handleWebhook(@RequestBody String rawBody) {
        log.info("Received npm webhook");

        try {
            JsonNode payload = objectMapper.readTree(rawBody);

            String event = payload.path("event").asText("");
            String packageName = payload.path("name").asText(null);
            String version = payload.path("version").asText(null);

            if (packageName == null || version == null) {
                log.warn("npm webhook missing required fields: name={}, version={}", packageName, version);
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Missing required fields: name, version"));
            }

            if (!"package:publish".equals(event) && !"package:change".equals(event)) {
                log.debug("Ignoring npm event type: {}", event);
                return ResponseEntity.ok(Map.of("status", "ignored", "reason", "unhandled event type"));
            }

            PackageReleaseEvent releaseEvent = new PackageReleaseEvent(
                    packageName,
                    version,
                    Ecosystem.NPM,
                    Instant.now()
            );

            publisher.publishPackageRelease(releaseEvent);

            log.info("npm package release published: {}@{}", packageName, version);

            return ResponseEntity.ok(Map.of(
                    "status", "processed",
                    "package", packageName,
                    "version", version
            ));

        } catch (Exception e) {
            log.error("Error processing npm webhook", e);
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", e.getMessage()));
        }
    }
}
