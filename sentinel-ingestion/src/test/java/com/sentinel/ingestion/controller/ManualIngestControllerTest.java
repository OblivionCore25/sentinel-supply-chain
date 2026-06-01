package com.sentinel.ingestion.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.MediaType;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.test.web.servlet.MockMvc;

import java.util.concurrent.CompletableFuture;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for the ManualIngestController using MockMvc.
 * Mocks Kafka and Redis to avoid requiring external infrastructure.
 */
@SpringBootTest
@AutoConfigureMockMvc
class ManualIngestControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private KafkaTemplate<String, Object> kafkaTemplate;

    @MockBean
    private StringRedisTemplate redisTemplate;

    @MockBean
    private ValueOperations<String, String> valueOperations;

    @Test
    @DisplayName("POST /api/ingest/vulnerability should accept valid payload")
    void shouldAcceptValidVulnerability() throws Exception {
        when(kafkaTemplate.send(anyString(), anyString(), any()))
                .thenReturn(CompletableFuture.completedFuture(null));
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        String payload = """
                {
                  "cveId": "CVE-2026-99999",
                  "packageName": "com.example:vulnerable-lib",
                  "affectedRange": ">=1.0.0, <1.5.3",
                  "cvssScore": 9.8,
                  "severity": "CRITICAL",
                  "description": "Remote code execution via crafted input"
                }
                """;

        mockMvc.perform(post("/api/ingest/vulnerability")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("accepted"))
                .andExpect(jsonPath("$.cveId").value("CVE-2026-99999"))
                .andExpect(jsonPath("$.topic").value("vuln.disclosed"));
    }

    @Test
    @DisplayName("POST /api/ingest/vulnerability should reject missing cveId")
    void shouldRejectMissingCveId() throws Exception {
        String payload = """
                {
                  "packageName": "com.example:lib",
                  "cvssScore": 5.0
                }
                """;

        mockMvc.perform(post("/api/ingest/vulnerability")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("POST /api/ingest/dependency-update should accept valid payload")
    void shouldAcceptValidDependencyUpdate() throws Exception {
        when(kafkaTemplate.send(anyString(), anyString(), any()))
                .thenReturn(CompletableFuture.completedFuture(null));
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        String payload = """
                {
                  "projectId": "my-api-service",
                  "packageName": "com.example:vulnerable-lib",
                  "previousVersion": "1.4.0",
                  "newVersion": "1.5.3",
                  "ecosystem": "MAVEN"
                }
                """;

        mockMvc.perform(post("/api/ingest/dependency-update")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payload))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("accepted"))
                .andExpect(jsonPath("$.projectId").value("my-api-service"));
    }
}
