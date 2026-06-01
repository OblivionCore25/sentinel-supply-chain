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
 * Normalizes NVD CVE 2.0 API responses into {@link VulnerabilityEvent} records.
 * <p>
 * NVD 2.0 response structure (per vulnerability):
 * <pre>
 * {
 *   "cve": {
 *     "id": "CVE-2026-12345",
 *     "descriptions": [{ "lang": "en", "value": "..." }],
 *     "published": "2026-01-15T...",
 *     "metrics": {
 *       "cvssMetricV31": [{
 *         "cvssData": { "baseScore": 9.8, "baseSeverity": "CRITICAL" }
 *       }]
 *     },
 *     "configurations": [{
 *       "nodes": [{
 *         "cpeMatch": [{
 *           "criteria": "cpe:2.3:a:vendor:product:*:...",
 *           "versionStartIncluding": "1.0.0",
 *           "versionEndExcluding": "1.5.3"
 *         }]
 *       }]
 *     }]
 *   }
 * }
 * </pre>
 */
@Component
public class NvdNormalizer {

    private static final Logger log = LoggerFactory.getLogger(NvdNormalizer.class);

    /**
     * Normalizes a list of NVD vulnerability items from the CVE 2.0 API response.
     *
     * @param vulnerabilities the "vulnerabilities" array from the NVD response
     * @return list of normalized VulnerabilityEvents
     */
    public List<VulnerabilityEvent> normalize(JsonNode vulnerabilities) {
        List<VulnerabilityEvent> events = new ArrayList<>();

        if (vulnerabilities == null || !vulnerabilities.isArray()) {
            return events;
        }

        for (JsonNode vulnWrapper : vulnerabilities) {
            try {
                JsonNode cve = vulnWrapper.path("cve");
                VulnerabilityEvent event = normalizeSingle(cve);
                if (event != null) {
                    events.add(event);
                }
            } catch (Exception e) {
                log.warn("Failed to normalize NVD vulnerability entry: {}", e.getMessage());
            }
        }

        return events;
    }

    /**
     * Normalizes a single NVD CVE JSON node.
     */
    public VulnerabilityEvent normalizeSingle(JsonNode cve) {
        if (cve == null || cve.isMissingNode()) {
            return null;
        }

        String cveId = cve.path("id").asText(null);
        if (cveId == null || cveId.isBlank()) {
            log.warn("NVD entry missing CVE ID, skipping");
            return null;
        }

        // Extract CVSS v3.1 score
        double cvssScore = extractCvssScore(cve);
        Severity severity = Severity.fromCvss(cvssScore);

        // Extract description (English)
        String description = extractDescription(cve);

        // Extract affected package info from CPE configurations
        String packageName = extractPackageName(cve);
        String affectedRange = extractAffectedRange(cve);

        // Extract published date
        Instant publishedAt = extractTimestamp(cve, "published");

        if (packageName == null || packageName.isBlank()) {
            // If we can't determine the package, use the CPE product as a fallback
            log.debug("No package name resolved for {}, using CPE product", cveId);
            packageName = "unknown:" + cveId;
        }

        return new VulnerabilityEvent(
                cveId,
                packageName,
                affectedRange,
                cvssScore,
                severity,
                description,
                EventSource.NVD,
                publishedAt,
                Instant.now()
        );
    }

    private double extractCvssScore(JsonNode cve) {
        // Try CVSS v3.1 first
        JsonNode cvssV31 = cve.path("metrics").path("cvssMetricV31");
        if (cvssV31.isArray() && !cvssV31.isEmpty()) {
            return cvssV31.get(0).path("cvssData").path("baseScore").asDouble(0.0);
        }

        // Fallback to CVSS v3.0
        JsonNode cvssV30 = cve.path("metrics").path("cvssMetricV30");
        if (cvssV30.isArray() && !cvssV30.isEmpty()) {
            return cvssV30.get(0).path("cvssData").path("baseScore").asDouble(0.0);
        }

        // Fallback to CVSS v2
        JsonNode cvssV2 = cve.path("metrics").path("cvssMetricV2");
        if (cvssV2.isArray() && !cvssV2.isEmpty()) {
            return cvssV2.get(0).path("cvssData").path("baseScore").asDouble(0.0);
        }

        return 0.0;
    }

    private String extractDescription(JsonNode cve) {
        JsonNode descriptions = cve.path("descriptions");
        if (descriptions.isArray()) {
            for (JsonNode desc : descriptions) {
                if ("en".equals(desc.path("lang").asText())) {
                    return desc.path("value").asText(null);
                }
            }
            // Fallback: take the first description
            if (!descriptions.isEmpty()) {
                return descriptions.get(0).path("value").asText(null);
            }
        }
        return null;
    }

    /**
     * Extracts a package name from CPE match criteria.
     * CPE format: cpe:2.3:a:vendor:product:version:...
     */
    private String extractPackageName(JsonNode cve) {
        JsonNode configurations = cve.path("configurations");
        if (configurations.isArray()) {
            for (JsonNode config : configurations) {
                JsonNode nodes = config.path("nodes");
                if (nodes.isArray()) {
                    for (JsonNode node : nodes) {
                        JsonNode cpeMatch = node.path("cpeMatch");
                        if (cpeMatch.isArray() && !cpeMatch.isEmpty()) {
                            String criteria = cpeMatch.get(0).path("criteria").asText("");
                            return parsePackageFromCpe(criteria);
                        }
                    }
                }
            }
        }
        return null;
    }

    /**
     * Parses vendor:product from a CPE 2.3 string.
     * Example: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" → "apache:log4j"
     */
    private String parsePackageFromCpe(String cpe) {
        if (cpe == null || cpe.isBlank()) return null;
        String[] parts = cpe.split(":");
        if (parts.length >= 5) {
            String vendor = parts[3];
            String product = parts[4];
            return vendor + ":" + product;
        }
        return null;
    }

    private String extractAffectedRange(JsonNode cve) {
        JsonNode configurations = cve.path("configurations");
        if (configurations.isArray()) {
            for (JsonNode config : configurations) {
                JsonNode nodes = config.path("nodes");
                if (nodes.isArray()) {
                    for (JsonNode node : nodes) {
                        JsonNode cpeMatch = node.path("cpeMatch");
                        if (cpeMatch.isArray()) {
                            for (JsonNode match : cpeMatch) {
                                return buildVersionRange(match);
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    private String buildVersionRange(JsonNode cpeMatch) {
        StringBuilder range = new StringBuilder();

        String startIncl = cpeMatch.path("versionStartIncluding").asText(null);
        String startExcl = cpeMatch.path("versionStartExcluding").asText(null);
        String endIncl = cpeMatch.path("versionEndIncluding").asText(null);
        String endExcl = cpeMatch.path("versionEndExcluding").asText(null);

        if (startIncl != null) range.append(">=").append(startIncl);
        else if (startExcl != null) range.append(">").append(startExcl);

        if (range.length() > 0 && (endIncl != null || endExcl != null)) {
            range.append(", ");
        }

        if (endExcl != null) range.append("<").append(endExcl);
        else if (endIncl != null) range.append("<=").append(endIncl);

        return range.length() > 0 ? range.toString() : null;
    }

    private Instant extractTimestamp(JsonNode cve, String field) {
        String ts = cve.path(field).asText(null);
        if (ts == null) return null;
        try {
            return Instant.parse(ts);
        } catch (DateTimeParseException e) {
            log.debug("Could not parse timestamp '{}' for field '{}'", ts, field);
            return null;
        }
    }
}
