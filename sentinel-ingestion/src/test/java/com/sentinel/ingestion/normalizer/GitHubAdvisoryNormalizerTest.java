package com.sentinel.ingestion.normalizer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.common.event.VulnerabilityEvent;
import com.sentinel.common.model.EventSource;
import com.sentinel.common.model.Severity;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class GitHubAdvisoryNormalizerTest {

    private GitHubAdvisoryNormalizer normalizer;
    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        normalizer = new GitHubAdvisoryNormalizer();
        mapper = new ObjectMapper();
    }

    @Test
    @DisplayName("Should normalize a GitHub webhook advisory payload")
    void normalizesWebhookPayload() throws Exception {
        String json = """
                {
                  "action": "published",
                  "security_advisory": {
                    "ghsa_id": "GHSA-abcd-1234-efgh",
                    "cve_id": "CVE-2026-98765",
                    "summary": "Critical RCE in log4j-core",
                    "description": "Remote code execution via JNDI lookup",
                    "severity": "critical",
                    "cvss": {"score": 10.0, "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
                    "vulnerabilities": [{
                      "package": {"name": "log4j-core", "ecosystem": "Maven"},
                      "vulnerable_version_range": ">= 2.0.0, < 2.17.1",
                      "first_patched_version": {"identifier": "2.17.1"}
                    }],
                    "published_at": "2026-06-01T10:00:00Z"
                  }
                }
                """;

        JsonNode payload = mapper.readTree(json);
        List<VulnerabilityEvent> events = normalizer.normalizeWebhook(payload);

        assertEquals(1, events.size());

        VulnerabilityEvent event = events.get(0);
        assertEquals("CVE-2026-98765", event.cveId());
        assertEquals("log4j-core", event.packageName());
        assertEquals(">= 2.0.0, < 2.17.1", event.affectedRange());
        assertEquals(10.0, event.cvssScore(), 0.01);
        assertEquals(Severity.CRITICAL, event.severity());
        assertEquals(EventSource.GITHUB, event.source());
    }

    @Test
    @DisplayName("Should ignore non-published/updated actions")
    void ignoresIrrelevantActions() throws Exception {
        String json = """
                {
                  "action": "withdrawn",
                  "security_advisory": {
                    "ghsa_id": "GHSA-xxxx",
                    "cve_id": "CVE-2026-00001"
                  }
                }
                """;

        JsonNode payload = mapper.readTree(json);
        List<VulnerabilityEvent> events = normalizer.normalizeWebhook(payload);

        assertTrue(events.isEmpty());
    }

    @Test
    @DisplayName("Should fall back to GHSA ID when CVE is not available")
    void fallsBackToGhsaId() throws Exception {
        String json = """
                {
                  "ghsa_id": "GHSA-only-ghsa-id",
                  "summary": "Moderate vulnerability",
                  "severity": "moderate",
                  "vulnerabilities": [{
                    "package": {"name": "lodash", "ecosystem": "npm"},
                    "vulnerable_version_range": "< 4.17.21"
                  }]
                }
                """;

        JsonNode advisory = mapper.readTree(json);
        List<VulnerabilityEvent> events = normalizer.normalizeAdvisory(advisory);

        assertEquals(1, events.size());
        assertEquals("GHSA-only-ghsa-id", events.get(0).cveId());
        assertEquals(Severity.MEDIUM, events.get(0).severity());
    }

    @Test
    @DisplayName("Should derive severity from string when CVSS score is absent")
    void derivesSeverityFromString() throws Exception {
        String json = """
                {
                  "ghsa_id": "GHSA-high-sev",
                  "severity": "high",
                  "vulnerabilities": [{
                    "package": {"name": "express", "ecosystem": "npm"},
                    "vulnerable_version_range": "< 4.18.0"
                  }]
                }
                """;

        JsonNode advisory = mapper.readTree(json);
        List<VulnerabilityEvent> events = normalizer.normalizeAdvisory(advisory);

        assertEquals(1, events.size());
        assertEquals(Severity.HIGH, events.get(0).severity());
    }
}
