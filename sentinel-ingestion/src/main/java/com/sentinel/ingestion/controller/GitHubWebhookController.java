package com.sentinel.ingestion.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.common.event.VulnerabilityEvent;
import com.sentinel.common.model.EventSource;
import com.sentinel.ingestion.dedup.EventDeduplicator;
import com.sentinel.ingestion.normalizer.GitHubAdvisoryNormalizer;
import com.sentinel.ingestion.publisher.EventPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/**
 * Receives GitHub Advisory webhook callbacks.
 * <p>
 * GitHub sends a POST with:
 * - Header: {@code X-Hub-Signature-256} (HMAC-SHA256 of the body)
 * - Header: {@code X-GitHub-Event} (event type, e.g., "security_advisory")
 * - Body: JSON with the advisory details
 * <p>
 * Validates the webhook signature using the configured secret, then normalizes
 * and publishes events to Kafka.
 */
@RestController
@RequestMapping("/webhooks/github")
public class GitHubWebhookController {

    private static final Logger log = LoggerFactory.getLogger(GitHubWebhookController.class);
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final String SIGNATURE_PREFIX = "sha256=";

    private final GitHubAdvisoryNormalizer normalizer;
    private final EventPublisher publisher;
    private final EventDeduplicator deduplicator;
    private final ObjectMapper objectMapper;
    private final String webhookSecret;

    public GitHubWebhookController(
            GitHubAdvisoryNormalizer normalizer,
            EventPublisher publisher,
            EventDeduplicator deduplicator,
            ObjectMapper objectMapper,
            @Value("${sentinel.ingestion.github.webhook-secret:}") String webhookSecret) {
        this.normalizer = normalizer;
        this.publisher = publisher;
        this.deduplicator = deduplicator;
        this.objectMapper = objectMapper;
        this.webhookSecret = webhookSecret;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> handleWebhook(
            @RequestHeader(value = "X-Hub-Signature-256", required = false) String signature,
            @RequestHeader(value = "X-GitHub-Event", required = false) String eventType,
            @RequestBody String rawBody) {

        log.info("Received GitHub webhook: event={}", eventType);

        // Verify signature if webhook secret is configured
        if (webhookSecret != null && !webhookSecret.isBlank()) {
            if (!verifySignature(rawBody, signature)) {
                log.warn("GitHub webhook signature verification failed");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Invalid signature"));
            }
        }

        // Only process security advisory events
        if (!"security_advisory".equals(eventType)) {
            log.debug("Ignoring non-advisory GitHub event: {}", eventType);
            return ResponseEntity.ok(Map.of("status", "ignored", "reason", "not a security_advisory event"));
        }

        try {
            JsonNode payload = objectMapper.readTree(rawBody);
            List<VulnerabilityEvent> events = normalizer.normalizeWebhook(payload);

            int published = 0;
            int deduplicated = 0;

            for (VulnerabilityEvent event : events) {
                if (deduplicator.isDuplicate(EventSource.GITHUB, event.cveId())) {
                    deduplicated++;
                    continue;
                }
                publisher.publishVulnerability(event);
                published++;
            }

            log.info("GitHub webhook processed: published={}, deduplicated={}", published, deduplicated);

            return ResponseEntity.ok(Map.of(
                    "status", "processed",
                    "published", published,
                    "deduplicated", deduplicated
            ));

        } catch (Exception e) {
            log.error("Error processing GitHub webhook", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * Verifies the HMAC-SHA256 signature of a GitHub webhook payload.
     */
    private boolean verifySignature(String payload, String signatureHeader) {
        if (signatureHeader == null || !signatureHeader.startsWith(SIGNATURE_PREFIX)) {
            return false;
        }

        try {
            Mac mac = Mac.getInstance(HMAC_SHA256);
            SecretKeySpec secretKey = new SecretKeySpec(
                    webhookSecret.getBytes(StandardCharsets.UTF_8), HMAC_SHA256);
            mac.init(secretKey);

            byte[] computedHash = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            String computedSignature = SIGNATURE_PREFIX + HexFormat.of().formatHex(computedHash);

            // Constant-time comparison to prevent timing attacks
            return constantTimeEquals(computedSignature, signatureHeader);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            log.error("HMAC signature computation failed", e);
            return false;
        }
    }

    /**
     * Constant-time string comparison to prevent timing attacks.
     */
    private boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) return false;
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }
}
