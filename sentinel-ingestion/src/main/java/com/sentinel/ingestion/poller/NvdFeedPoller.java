package com.sentinel.ingestion.poller;

import com.fasterxml.jackson.databind.JsonNode;
import com.sentinel.common.event.VulnerabilityEvent;
import com.sentinel.common.model.EventSource;
import com.sentinel.ingestion.dedup.EventDeduplicator;
import com.sentinel.ingestion.normalizer.NvdNormalizer;
import com.sentinel.ingestion.publisher.EventPublisher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Polls the NVD CVE 2.0 API for recently modified vulnerabilities.
 * <p>
 * Uses the free API key (50 req/30s) with NVD-recommended 6-second delays.
 * Queries for CVEs modified since the last successful poll.
 *
 * @see <a href="https://nvd.nist.gov/developers/vulnerabilities">NVD API Documentation</a>
 */
@Component
public class NvdFeedPoller {

    private static final Logger log = LoggerFactory.getLogger(NvdFeedPoller.class);

    private final WebClient webClient;
    private final NvdNormalizer normalizer;
    private final EventPublisher publisher;
    private final EventDeduplicator deduplicator;
    private final long requestDelayMs;

    /**
     * Tracks the last modification timestamp for incremental polling.
     */
    private final AtomicReference<Instant> lastPollTimestamp = new AtomicReference<>(
            Instant.now().minus(24, ChronoUnit.HOURS)
    );

    public NvdFeedPoller(
            NvdNormalizer normalizer,
            EventPublisher publisher,
            EventDeduplicator deduplicator,
            @Value("${sentinel.ingestion.nvd.base-url}") String baseUrl,
            @Value("${sentinel.ingestion.nvd.api-key:}") String apiKey,
            @Value("${sentinel.ingestion.nvd.request-delay-ms:6000}") long requestDelayMs) {
        this.normalizer = normalizer;
        this.publisher = publisher;
        this.deduplicator = deduplicator;
        this.requestDelayMs = requestDelayMs;

        WebClient.Builder builder = WebClient.builder()
                .baseUrl(baseUrl)
                .defaultHeader("Content-Type", "application/json");

        // Add API key header if configured
        if (apiKey != null && !apiKey.isBlank()) {
            builder.defaultHeader("apiKey", apiKey);
            log.info("NVD API key configured — using 50 req/30s rate limit");
        } else {
            log.warn("NVD API key not configured — limited to 5 req/30s. "
                    + "Get a free key at https://nvd.nist.gov/developers/request-an-api-key");
        }

        this.webClient = builder.build();
    }

    /**
     * Polls NVD for CVEs modified since the last poll.
     * Runs on a configurable schedule (default: every hour).
     */
    @Scheduled(fixedDelayString = "${sentinel.ingestion.nvd.poll-interval-ms:3600000}",
               initialDelayString = "${sentinel.ingestion.nvd.initial-delay-ms:30000}")
    public void poll() {
        Instant startTime = lastPollTimestamp.get();
        Instant endTime = Instant.now();

        log.info("NVD poll starting: fetching CVEs modified since {}", startTime);

        try {
            int totalPublished = 0;
            int totalDeduplicated = 0;
            int startIndex = 0;
            int totalResults;

            do {
                // NVD recommends 6-second delays between requests
                if (startIndex > 0) {
                    Thread.sleep(requestDelayMs);
                }

                JsonNode response = fetchCves(startTime, endTime, startIndex);
                if (response == null) {
                    log.warn("NVD API returned null response");
                    break;
                }

                totalResults = response.path("totalResults").asInt(0);
                JsonNode vulnerabilities = response.path("vulnerabilities");

                List<VulnerabilityEvent> events = normalizer.normalize(vulnerabilities);

                for (VulnerabilityEvent event : events) {
                    if (deduplicator.isDuplicate(EventSource.NVD, event.cveId())) {
                        totalDeduplicated++;
                        continue;
                    }
                    publisher.publishVulnerability(event);
                    totalPublished++;
                }

                startIndex += response.path("resultsPerPage").asInt(20);
                log.debug("NVD page processed: startIndex={}, totalResults={}", startIndex, totalResults);

            } while (startIndex < totalResults);

            lastPollTimestamp.set(endTime);
            log.info("NVD poll complete: published={}, deduplicated={}, totalFromApi={}",
                    totalPublished, totalDeduplicated, startIndex);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("NVD poll interrupted");
        } catch (Exception e) {
            log.error("NVD poll failed", e);
        }
    }

    /**
     * Fetches a page of CVEs from the NVD API.
     */
    private JsonNode fetchCves(Instant startTime, Instant endTime, int startIndex) {
        String start = DateTimeFormatter.ISO_INSTANT.format(startTime.truncatedTo(ChronoUnit.SECONDS));
        String end = DateTimeFormatter.ISO_INSTANT.format(endTime.truncatedTo(ChronoUnit.SECONDS));

        return webClient.get()
                .uri(uriBuilder -> uriBuilder
                        .queryParam("lastModStartDate", start)
                        .queryParam("lastModEndDate", end)
                        .queryParam("startIndex", startIndex)
                        .queryParam("resultsPerPage", 20)
                        .build())
                .retrieve()
                .bodyToMono(JsonNode.class)
                .doOnError(e -> log.error("NVD API request failed: {}", e.getMessage()))
                .onErrorReturn(null) // Return null so the poll loop can handle it gracefully
                .block();
    }
}
