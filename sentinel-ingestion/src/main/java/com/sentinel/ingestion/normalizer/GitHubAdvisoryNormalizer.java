package com.sentinel.ingestion.normalizer;

import com.fasterxml.jackson.databind.JsonNode;
import com.sentinel.common.event.VulnerabilityEvent;
import com.sentinel.common.model.EventSource;
import com.sentinel.common.model.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Normalizes GitHub Advisory Database responses (both webhook and GraphQL poller)
 * into {@link VulnerabilityEvent} records.
 * <p>
 * GitHub Advisory webhook payload structure:
 * <pre>
 * {
 *   "action": "published",
 *   "security_advisory": {
 *     "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
 *     "cve_id": "CVE-2026-12345",
 *     "summary": "...",
 *     "description": "...",
 *     "severity": "critical",
 *     "cvss": { "score": 9.8, "vector_string": "..." },
 *     "vulnerabilities": [{
 *       "package": { "name": "log4j-core", "ecosystem": "Maven" },
 *       "vulnerable_version_range": ">= 2.0.0, < 2.17.1",
 *       "first_patched_version": { "identifier": "2.17.1" }
 *     }],
 *     "published_at": "2026-01-15T..."
 *   }
 * }
 * </pre>
 *
 * GraphQL response node structure is similar but nested under "securityAdvisory".
 */
@Component
public class GitHubAdvisoryNormalizer {

    private static final Logger log = LoggerFactory.getLogger(GitHubAdvisoryNormalizer.class);

    /**
     * Normalizes a GitHub webhook payload for a security advisory event.
     *
     * @param payload the full webhook JSON body
     * @return list of vulnerability events (one per affected package)
     */
    public List<VulnerabilityEvent> normalizeWebhook(JsonNode payload) {
        String action = payload.path("action").asText("");
        if (!"published".equals(action) && !"updated".equals(action)) {
            log.debug("Ignoring GitHub advisory action: {}", action);
            return List.of();
        }

        JsonNode advisory = payload.path("security_advisory");
        return normalizeAdvisory(advisory);
    }

    /**
     * Normalizes a single GitHub security advisory (from either webhook or GraphQL).
     */
    public List<VulnerabilityEvent> normalizeAdvisory(JsonNode advisory) {
        List<VulnerabilityEvent> events = new ArrayList<>();

        if (advisory == null || advisory.isMissingNode()) {
            return events;
        }

        String ghsaId = advisory.path("ghsa_id").asText(
                advisory.path("ghsaId").asText(null) // GraphQL field name
        );
        String cveId = advisory.path("cve_id").asText(
                advisory.path("cveId").asText(null) // GraphQL field name
        );

        // Use CVE ID if available, fall back to GHSA ID
        String vulnerabilityId = (cveId != null && !cveId.isBlank()) ? cveId : ghsaId;
        if (vulnerabilityId == null) {
            log.warn("GitHub advisory missing both CVE and GHSA IDs, skipping");
            return events;
        }

        String summary = advisory.path("summary").asText(null);
        String description = advisory.path("description").asText(summary);

        double cvssScore = extractCvssScore(advisory);
        Severity severity = cvssScore > 0 ? Severity.fromCvss(cvssScore) : extractSeverity(advisory);

        Instant publishedAt = extractTimestamp(advisory, "published_at", "publishedAt");

        // Create one event per affected package
        JsonNode vulnerabilities = advisory.path("vulnerabilities");
        if (vulnerabilities.isArray()) {
            for (JsonNode vulnPkg : vulnerabilities) {
                String packageName = extractPackageName(vulnPkg);
                String affectedRange = extractAffectedRange(vulnPkg);

                if (packageName != null && !packageName.isBlank()) {
                    events.add(new VulnerabilityEvent(
                            vulnerabilityId,
                            packageName,
                            affectedRange,
                            cvssScore,
                            severity,
                            description,
                            EventSource.GITHUB,
                            publishedAt,
                            Instant.now()
                    ));
                }
            }
        }

        // If no package-level entries, create a single event with advisory-level data
        if (events.isEmpty() && vulnerabilityId != null) {
            events.add(new VulnerabilityEvent(
                    vulnerabilityId,
                    "unknown",
                    null,
                    cvssScore,
                    severity,
                    description,
                    EventSource.GITHUB,
                    publishedAt,
                    Instant.now()
            ));
        }

        return events;
    }

    private double extractCvssScore(JsonNode advisory) {
        // Webhook format
        JsonNode cvss = advisory.path("cvss");
        if (!cvss.isMissingNode()) {
            return cvss.path("score").asDouble(0.0);
        }

        // GraphQL format
        double score = advisory.path("cvssScore").asDouble(0.0);
        if (score > 0) return score;

        // Fall back to severity-based estimate
        return 0.0;
    }

    /**
     * Maps GitHub severity strings to our Severity enum when CVSS score isn't available.
     */
    private Severity extractSeverity(JsonNode advisory) {
        String githubSeverity = advisory.path("severity").asText("").toUpperCase();
        return switch (githubSeverity) {
            case "CRITICAL" -> Severity.CRITICAL;
            case "HIGH" -> Severity.HIGH;
            case "MODERATE", "MEDIUM" -> Severity.MEDIUM;
            case "LOW" -> Severity.LOW;
            default -> Severity.MEDIUM; // Conservative default
        };
    }

    private String extractPackageName(JsonNode vulnPackage) {
        // Webhook structure
        JsonNode pkg = vulnPackage.path("package");
        if (!pkg.isMissingNode()) {
            String name = pkg.path("name").asText(null);
            String ecosystem = pkg.path("ecosystem").asText("");

            if (name != null) {
                // Maven packages from GitHub don't include the group ID in the name field;
                // they're listed separately. Return as-is for now.
                return name;
            }
        }

        // GraphQL structure
        return vulnPackage.path("vulnerablePackage").path("name").asText(null);
    }

    private String extractAffectedRange(JsonNode vulnPackage) {
        // Webhook: "vulnerable_version_range" field
        String range = vulnPackage.path("vulnerable_version_range").asText(null);
        if (range != null) return range;

        // GraphQL: "vulnerableVersionRange" field
        return vulnPackage.path("vulnerableVersionRange").asText(null);
    }

    private Instant extractTimestamp(JsonNode node, String... fieldNames) {
        for (String field : fieldNames) {
            String ts = node.path(field).asText(null);
            if (ts != null) {
                try {
                    return Instant.parse(ts);
                } catch (DateTimeParseException e) {
                    log.debug("Could not parse timestamp '{}' for field '{}'", ts, field);
                }
            }
        }
        return null;
    }
}
