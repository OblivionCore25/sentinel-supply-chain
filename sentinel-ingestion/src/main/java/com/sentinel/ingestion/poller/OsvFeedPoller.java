package com.sentinel.ingestion.poller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sentinel.common.event.VulnerabilityEvent;
import com.sentinel.common.model.EventSource;
import com.sentinel.ingestion.dedup.EventDeduplicator;
import com.sentinel.ingestion.normalizer.OsvNormalizer;
import com.sentinel.ingestion.publisher.EventPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.List;

/**
 * Polls the OSV.dev API for known vulnerabilities in monitored packages.
 * <p>
 * The OSV API is completely free with no rate limits.
 * Queries both Maven and npm ecosystems.
 *
 * @see <a href="https://osv.dev/docs/">OSV API Documentation</a>
 */
@Component
public class OsvFeedPoller {

    private static final Logger log = LoggerFactory.getLogger(OsvFeedPoller.class);

    private final WebClient webClient;
    private final OsvNormalizer normalizer;
    private final EventPublisher publisher;
    private final EventDeduplicator deduplicator;
    private final ObjectMapper objectMapper;

    public OsvFeedPoller(
            OsvNormalizer normalizer,
            EventPublisher publisher,
            EventDeduplicator deduplicator,
            ObjectMapper objectMapper,
            @Value("${sentinel.ingestion.osv.base-url}") String baseUrl) {
        this.normalizer = normalizer;
        this.publisher = publisher;
        this.deduplicator = deduplicator;
        this.objectMapper = objectMapper;
        this.webClient = WebClient.builder()
                .baseUrl(baseUrl)
                .defaultHeader("Content-Type", "application/json")
                .build();
    }

    /**
     * Polls OSV for vulnerabilities affecting well-known packages.
     * Runs on a configurable schedule (default: every 30 minutes).
     */
    @Scheduled(fixedDelayString = "${sentinel.ingestion.osv.poll-interval-ms:1800000}",
               initialDelayString = "${sentinel.ingestion.osv.initial-delay-ms:15000}")
    public void poll() {
        log.info("OSV poll starting");

        int totalPublished = 0;
        int totalDeduplicated = 0;

        // Query a curated list of commonly targeted ecosystems
        // In production, this list would come from the monitored projects database
        totalPublished += queryEcosystem("Maven");
        totalPublished += queryEcosystem("npm");

        log.info("OSV poll complete: published={}", totalPublished);
    }

    /**
     * Queries OSV for recently disclosed vulnerabilities in a given ecosystem.
     * Uses the /v1/query endpoint for broad ecosystem queries.
     */
    private int queryEcosystem(String ecosystem) {
        try {
            // Query for vulnerabilities modified recently
            ObjectNode requestBody = objectMapper.createObjectNode();
            ObjectNode pkg = objectMapper.createObjectNode();
            pkg.put("ecosystem", ecosystem);
            requestBody.set("package", pkg);

            JsonNode response = webClient.post()
                    .uri("/query")
                    .bodyValue(requestBody)
                    .retrieve()
                    .bodyToMono(JsonNode.class)
                    .doOnError(e -> log.error("OSV API request failed for ecosystem {}: {}",
                            ecosystem, e.getMessage()))
                    .block();

            if (response == null) {
                log.warn("OSV returned null response for ecosystem {}", ecosystem);
                return 0;
            }

            JsonNode vulns = response.path("vulns");
            if (!vulns.isArray() || vulns.isEmpty()) {
                log.debug("No vulnerabilities returned for ecosystem {}", ecosystem);
                return 0;
            }

            List<VulnerabilityEvent> events = normalizer.normalize(vulns);
            int published = 0;

            for (VulnerabilityEvent event : events) {
                if (deduplicator.isDuplicate(EventSource.OSV, event.cveId())) {
                    continue;
                }
                publisher.publishVulnerability(event);
                published++;
            }

            log.debug("OSV ecosystem {} processed: {} events published", ecosystem, published);
            return published;

        } catch (Exception e) {
            log.error("OSV poll failed for ecosystem {}", ecosystem, e);
            return 0;
        }
    }

    /**
     * Queries OSV for vulnerabilities affecting a specific package.
     * This can be called on-demand when a new project is registered.
     *
     * @param packageName the package name (e.g., "org.apache.logging.log4j:log4j-core")
     * @param version     the package version (e.g., "2.14.1")
     * @param ecosystem   the ecosystem (e.g., "Maven")
     * @return list of vulnerability events
     */
    public List<VulnerabilityEvent> queryPackage(String packageName, String version, String ecosystem) {
        try {
            ObjectNode requestBody = objectMapper.createObjectNode();
            ObjectNode pkg = objectMapper.createObjectNode();
            pkg.put("name", packageName);
            pkg.put("ecosystem", ecosystem);
            requestBody.set("package", pkg);

            if (version != null && !version.isBlank()) {
                requestBody.put("version", version);
            }

            JsonNode response = webClient.post()
                    .uri("/query")
                    .bodyValue(requestBody)
                    .retrieve()
                    .bodyToMono(JsonNode.class)
                    .block();

            if (response == null) {
                return List.of();
            }

            return normalizer.normalize(response.path("vulns"));

        } catch (Exception e) {
            log.error("OSV query failed for package {}@{}", packageName, version, e);
            return List.of();
        }
    }
}
