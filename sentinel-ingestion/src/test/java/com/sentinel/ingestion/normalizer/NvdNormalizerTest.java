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

class NvdNormalizerTest {

    private NvdNormalizer normalizer;
    private ObjectMapper mapper;

    @BeforeEach
    void setUp() {
        normalizer = new NvdNormalizer();
        mapper = new ObjectMapper();
    }

    @Test
    @DisplayName("Should normalize a standard NVD CVE with CVSS v3.1")
    void normalizesStandardCve() throws Exception {
        String json = """
                [{
                  "cve": {
                    "id": "CVE-2026-12345",
                    "descriptions": [
                      {"lang": "en", "value": "Remote code execution in example-lib"}
                    ],
                    "published": "2026-01-15T10:00:00.000Z",
                    "metrics": {
                      "cvssMetricV31": [{
                        "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}
                      }]
                    },
                    "configurations": [{
                      "nodes": [{
                        "cpeMatch": [{
                          "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
                          "versionStartIncluding": "2.0.0",
                          "versionEndExcluding": "2.17.1"
                        }]
                      }]
                    }]
                  }
                }]
                """;

        JsonNode vulnerabilities = mapper.readTree(json);
        List<VulnerabilityEvent> events = normalizer.normalize(vulnerabilities);

        assertEquals(1, events.size());

        VulnerabilityEvent event = events.get(0);
        assertEquals("CVE-2026-12345", event.cveId());
        assertEquals("apache:log4j", event.packageName());
        assertEquals(">=2.0.0, <2.17.1", event.affectedRange());
        assertEquals(9.8, event.cvssScore(), 0.01);
        assertEquals(Severity.CRITICAL, event.severity());
        assertEquals(EventSource.NVD, event.source());
        assertNotNull(event.description());
        assertNotNull(event.publishedAt());
    }

    @Test
    @DisplayName("Should handle CVE with only CVSS v2")
    void handlesCvssV2Fallback() throws Exception {
        String json = """
                [{
                  "cve": {
                    "id": "CVE-2020-99999",
                    "descriptions": [{"lang": "en", "value": "Old vulnerability"}],
                    "metrics": {
                      "cvssMetricV2": [{
                        "cvssData": {"baseScore": 6.5}
                      }]
                    },
                    "configurations": [{
                      "nodes": [{
                        "cpeMatch": [{
                          "criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
                        }]
                      }]
                    }]
                  }
                }]
                """;

        JsonNode vulnerabilities = mapper.readTree(json);
        List<VulnerabilityEvent> events = normalizer.normalize(vulnerabilities);

        assertEquals(1, events.size());
        assertEquals(6.5, events.get(0).cvssScore(), 0.01);
        assertEquals(Severity.MEDIUM, events.get(0).severity());
    }

    @Test
    @DisplayName("Should return empty list for null input")
    void handlesNullInput() {
        List<VulnerabilityEvent> events = normalizer.normalize(null);
        assertTrue(events.isEmpty());
    }

    @Test
    @DisplayName("Should skip entries without CVE ID")
    void skipsMissingCveId() throws Exception {
        String json = """
                [{
                  "cve": {
                    "descriptions": [{"lang": "en", "value": "No ID"}],
                    "metrics": {}
                  }
                }]
                """;

        JsonNode vulnerabilities = mapper.readTree(json);
        List<VulnerabilityEvent> events = normalizer.normalize(vulnerabilities);
        assertTrue(events.isEmpty());
    }
}
