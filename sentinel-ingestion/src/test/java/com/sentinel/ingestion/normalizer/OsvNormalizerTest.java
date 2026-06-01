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

class OsvNormalizerTest {

    private OsvNormalizer normalizer;
    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        normalizer = new OsvNormalizer();
        mapper = new ObjectMapper();
    }

    @Test
    @DisplayName("Should normalize OSV vulnerability with affected ranges")
    void normalizesOsvVulnerability() throws Exception {
        String json = """
                [{
                  "id": "GHSA-abcd-efgh-ijkl",
                  "summary": "SQL injection in example-db",
                  "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                  "affected": [{
                    "package": {"name": "example-db", "ecosystem": "npm"},
                    "ranges": [{
                      "type": "ECOSYSTEM",
                      "events": [
                        {"introduced": "1.0.0"},
                        {"fixed": "1.5.3"}
                      ]
                    }]
                  }],
                  "published": "2026-02-20T12:00:00Z",
                  "aliases": ["CVE-2026-54321"]
                }]
                """;

        JsonNode vulns = mapper.readTree(json);
        List<VulnerabilityEvent> events = normalizer.normalize(vulns);

        assertEquals(1, events.size());

        VulnerabilityEvent event = events.get(0);
        assertEquals("CVE-2026-54321", event.cveId()); // Resolved from aliases
        assertEquals("example-db", event.packageName());
        assertEquals(">=1.0.0, <1.5.3", event.affectedRange());
        assertEquals(7.5, event.cvssScore(), 0.01);
        assertEquals(Severity.HIGH, event.severity());
        assertEquals(EventSource.OSV, event.source());
    }

    @Test
    @DisplayName("Should use OSV ID when no CVE alias exists")
    void usesOsvIdWhenNoCveAlias() throws Exception {
        String json = """
                [{
                  "id": "GHSA-xxxx-yyyy-zzzz",
                  "summary": "XSS vulnerability",
                  "affected": [{
                    "package": {"name": "vue-template-compiler", "ecosystem": "npm"},
                    "ranges": [{
                      "type": "ECOSYSTEM",
                      "events": [{"introduced": "2.0.0"}, {"fixed": "2.7.15"}]
                    }]
                  }],
                  "aliases": []
                }]
                """;

        JsonNode vulns = mapper.readTree(json);
        List<VulnerabilityEvent> events = normalizer.normalize(vulns);

        assertEquals(1, events.size());
        assertEquals("GHSA-xxxx-yyyy-zzzz", events.get(0).cveId());
    }

    @Test
    @DisplayName("Should create multiple events for multiple affected packages")
    void createsMultipleEventsForMultiplePackages() throws Exception {
        String json = """
                [{
                  "id": "CVE-2026-11111",
                  "summary": "Affects two packages",
                  "severity": [{"type": "CVSS_V3", "score": "5.0"}],
                  "affected": [
                    {
                      "package": {"name": "pkg-a", "ecosystem": "Maven"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]
                    },
                    {
                      "package": {"name": "pkg-b", "ecosystem": "Maven"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0"}, {"fixed": "3.0"}]}]
                    }
                  ]
                }]
                """;

        JsonNode vulns = mapper.readTree(json);
        List<VulnerabilityEvent> events = normalizer.normalize(vulns);

        assertEquals(2, events.size());
        assertEquals("pkg-a", events.get(0).packageName());
        assertEquals("pkg-b", events.get(1).packageName());
    }

    @Test
    @DisplayName("Should handle empty input")
    void handlesEmptyInput() {
        List<VulnerabilityEvent> events = normalizer.normalize(null);
        assertTrue(events.isEmpty());
    }
}
