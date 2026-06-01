package com.sentinel.ingestion.normalizer;

import com.fasterxml.jackson.databind.JsonNode;
import com.sentinel.common.event.VulnerabilityEvent;
import com.sentinel.common.model.Ecosystem;
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
 * Normalizes OSV.dev API responses into {@link VulnerabilityEvent} records.
 * <p>
 * OSV response structure (per vulnerability):
 * <pre>
 * {
 *   "id": "GHSA-xxxx-xxxx-xxxx" or "CVE-2026-xxxxx",
 *   "summary": "...",
 *   "details": "...",
 *   "severity": [{ "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..." }],
 *   "affected": [{
 *     "package": { "name": "org.example:lib", "ecosystem": "Maven" },
 *     "ranges": [{
 *       "type": "ECOSYSTEM",
 *       "events": [
 *         { "introduced": "1.0.0" },
 *         { "fixed": "1.5.3" }
 *       ]
 *     }]
 *   }],
 *   "published": "2026-01-15T...",
 *   "aliases": ["CVE-2026-12345"]
 * }
 * </pre>
 */
@Component
public class OsvNormalizer {

    private static final Logger log = LoggerFactory.getLogger(OsvNormalizer.class);

    /**
     * Normalizes a list of OSV vulnerabilities.
     *
     * @param vulns JSON array of OSV vulnerability objects
     * @return list of normalized events
     */
    public List<VulnerabilityEvent> normalize(JsonNode vulns) {
        List<VulnerabilityEvent> events = new ArrayList<>();

        if (vulns == null || !vulns.isArray()) {
            return events;
        }

        for (JsonNode vuln : vulns) {
            try {
                List<VulnerabilityEvent> normalized = normalizeSingle(vuln);
                events.addAll(normalized);
            } catch (Exception e) {
                log.warn("Failed to normalize OSV vulnerability: {}", e.getMessage());
            }
        }

        return events;
    }

    /**
     * Normalizes a single OSV vulnerability.
     * One OSV entry can produce multiple events (one per affected package).
     */
    public List<VulnerabilityEvent> normalizeSingle(JsonNode vuln) {
        List<VulnerabilityEvent> events = new ArrayList<>();

        String osvId = vuln.path("id").asText(null);
        if (osvId == null) {
            log.warn("OSV entry missing ID, skipping");
            return events;
        }

        // Resolve CVE ID: use aliases if the primary ID isn't a CVE
        String cveId = resolveCveId(osvId, vuln.path("aliases"));

        String summary = vuln.path("summary").asText(null);
        String details = vuln.path("details").asText(null);
        String description = summary != null ? summary : details;

        double cvssScore = extractCvssScore(vuln);
        Severity severity = Severity.fromCvss(cvssScore);
        Instant publishedAt = extractTimestamp(vuln.path("published").asText(null));

        // Create an event per affected package
        JsonNode affected = vuln.path("affected");
        if (affected.isArray()) {
            for (JsonNode pkg : affected) {
                String packageName = extractPackageName(pkg);
                String affectedRange = extractAffectedRange(pkg);

                if (packageName != null && !packageName.isBlank()) {
                    events.add(new VulnerabilityEvent(
                            cveId,
                            packageName,
                            affectedRange,
                            cvssScore,
                            severity,
                            description,
                            EventSource.OSV,
                            publishedAt,
                            Instant.now()
                    ));
                }
            }
        }

        return events;
    }

    /**
     * Resolves a CVE ID from the OSV primary ID or aliases.
     * OSV uses GHSA- or PYSEC- or other prefixes; we prefer a CVE ID when available.
     */
    private String resolveCveId(String osvId, JsonNode aliases) {
        if (osvId.startsWith("CVE-")) {
            return osvId;
        }

        if (aliases != null && aliases.isArray()) {
            for (JsonNode alias : aliases) {
                String id = alias.asText("");
                if (id.startsWith("CVE-")) {
                    return id;
                }
            }
        }

        // No CVE alias found; use the OSV ID as-is
        return osvId;
    }

    /**
     * Extracts CVSS score from OSV severity field.
     * OSV stores the full CVSS vector string; we parse the base score from it.
     */
    private double extractCvssScore(JsonNode vuln) {
        JsonNode severity = vuln.path("severity");
        if (severity.isArray()) {
            for (JsonNode entry : severity) {
                if ("CVSS_V3".equals(entry.path("type").asText())) {
                    String vector = entry.path("score").asText("");
                    return parseCvssBaseScore(vector);
                }
            }
        }

        // Fallback: try database_specific.cvss.score
        JsonNode dbSpecific = vuln.path("database_specific");
        if (dbSpecific.has("severity")) {
            return severityToEstimatedCvss(dbSpecific.path("severity").asText(""));
        }

        return 0.0;
    }

    /**
     * Parses the base score from a CVSS v3 vector string.
     * This is a simplified parser; in production you'd use a CVSS library.
     */
    private double parseCvssBaseScore(String vector) {
        // The vector string doesn't directly contain the numeric score in all cases.
        // OSV sometimes stores just the vector, other times "score" is the numeric value.
        try {
            return Double.parseDouble(vector);
        } catch (NumberFormatException e) {
            // If it's a vector string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            // we'd need a CVSS calculator. For now, estimate from vector components.
            if (vector.contains("AV:N") && vector.contains("C:H") && vector.contains("I:H")) {
                return 9.0; // Network-accessible, high impact → Critical
            } else if (vector.contains("AV:N") && (vector.contains("C:H") || vector.contains("I:H"))) {
                return 7.5; // High
            } else if (vector.contains("AV:N")) {
                return 5.0; // Medium
            }
            return 5.0; // Default estimate
        }
    }

    private double severityToEstimatedCvss(String severity) {
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> 9.5;
            case "HIGH" -> 7.5;
            case "MODERATE", "MEDIUM" -> 5.0;
            case "LOW" -> 2.5;
            default -> 0.0;
        };
    }

    private String extractPackageName(JsonNode affectedEntry) {
        JsonNode pkg = affectedEntry.path("package");
        String name = pkg.path("name").asText(null);
        String ecosystem = pkg.path("ecosystem").asText("");

        if (name == null) return null;

        // Normalize ecosystem prefix for consistency
        // Maven packages: "org.apache.logging.log4j:log4j-core"
        // npm packages: "lodash"
        return name;
    }

    private String extractAffectedRange(JsonNode affectedEntry) {
        JsonNode ranges = affectedEntry.path("ranges");
        if (!ranges.isArray() || ranges.isEmpty()) return null;

        // Take the first ECOSYSTEM range
        for (JsonNode range : ranges) {
            if ("ECOSYSTEM".equals(range.path("type").asText())) {
                return buildRangeFromEvents(range.path("events"));
            }
        }

        // Fallback to first range of any type
        return buildRangeFromEvents(ranges.get(0).path("events"));
    }

    /**
     * Builds a version range string from OSV range events.
     * Events: [{"introduced": "1.0.0"}, {"fixed": "1.5.3"}]
     * Result: ">=1.0.0, <1.5.3"
     */
    private String buildRangeFromEvents(JsonNode events) {
        if (events == null || !events.isArray()) return null;

        String introduced = null;
        String fixed = null;

        for (JsonNode event : events) {
            if (event.has("introduced")) {
                String val = event.path("introduced").asText();
                if (!"0".equals(val)) {
                    introduced = val;
                }
            }
            if (event.has("fixed")) {
                fixed = event.path("fixed").asText();
            }
        }

        StringBuilder range = new StringBuilder();
        if (introduced != null) range.append(">=").append(introduced);
        if (introduced != null && fixed != null) range.append(", ");
        if (fixed != null) range.append("<").append(fixed);

        return range.length() > 0 ? range.toString() : null;
    }

    private Instant extractTimestamp(String ts) {
        if (ts == null) return null;
        try {
            return Instant.parse(ts);
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
