package com.sentinel.ingestion.poller;

import com.fasterxml.jackson.databind.JsonNode;
import com.sentinel.common.event.VulnerabilityEvent;
import com.sentinel.common.model.EventSource;
import com.sentinel.ingestion.dedup.EventDeduplicator;
import com.sentinel.ingestion.normalizer.GitHubAdvisoryNormalizer;
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
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Polls the GitHub Advisory Database via GraphQL API for recently updated advisories.
 * <p>
 * Uses a free GitHub Personal Access Token (no special scopes needed).
 * Rate limit: 5,000 points/hour.
 *
 * @see <a href="https://docs.github.com/en/graphql/reference/objects#securityadvisory">GitHub GraphQL SecurityAdvisory</a>
 */
@Component
public class GitHubAdvisoryPoller {

    private static final Logger log = LoggerFactory.getLogger(GitHubAdvisoryPoller.class);

    private final WebClient webClient;
    private final GitHubAdvisoryNormalizer normalizer;
    private final EventPublisher publisher;
    private final EventDeduplicator deduplicator;
    private final boolean enabled;

    private final AtomicReference<Instant> lastPollTimestamp = new AtomicReference<>(
            Instant.now().minus(24, ChronoUnit.HOURS)
    );

    /**
     * GraphQL query to fetch recently updated security advisories.
     * Fetches advisories for both MAVEN and NPM ecosystems.
     */
    private static final String GRAPHQL_QUERY = """
            query($updatedSince: DateTime!, $after: String) {
              securityAdvisories(
                updatedSince: $updatedSince
                first: 25
                after: $after
                orderBy: {field: UPDATED_AT, direction: DESC}
              ) {
                totalCount
                pageInfo {
                  hasNextPage
                  endCursor
                }
                nodes {
                  ghsaId
                  summary
                  description
                  severity
                  publishedAt
                  updatedAt
                  cvss {
                    score
                    vectorString
                  }
                  identifiers {
                    type
                    value
                  }
                  vulnerabilities(first: 20, ecosystem: %s) {
                    nodes {
                      package {
                        name
                        ecosystem
                      }
                      vulnerableVersionRange
                      firstPatchedVersion {
                        identifier
                      }
                    }
                  }
                }
              }
            }
            """;

    public GitHubAdvisoryPoller(
            GitHubAdvisoryNormalizer normalizer,
            EventPublisher publisher,
            EventDeduplicator deduplicator,
            @Value("${sentinel.ingestion.github.graphql-url}") String graphqlUrl,
            @Value("${sentinel.ingestion.github.pat:}") String pat) {
        this.normalizer = normalizer;
        this.publisher = publisher;
        this.deduplicator = deduplicator;

        this.enabled = pat != null && !pat.isBlank();

        WebClient.Builder builder = WebClient.builder()
                .baseUrl(graphqlUrl)
                .defaultHeader("Content-Type", "application/json");

        if (enabled) {
            builder.defaultHeader("Authorization", "Bearer " + pat);
            log.info("GitHub Advisory poller enabled (PAT configured)");
        } else {
            log.warn("GitHub Advisory poller disabled — no GITHUB_PAT configured");
        }

        this.webClient = builder.build();
    }

    /**
     * Polls GitHub Advisory Database for recently updated advisories.
     * Runs on a configurable schedule (default: every 2 hours).
     */
    @Scheduled(fixedDelayString = "${sentinel.ingestion.github.poll-interval-ms:7200000}",
               initialDelayString = "${sentinel.ingestion.github.initial-delay-ms:45000}")
    public void poll() {
        if (!enabled) {
            log.debug("GitHub Advisory poller skipped — not configured");
            return;
        }

        Instant since = lastPollTimestamp.get();
        log.info("GitHub Advisory poll starting: fetching advisories updated since {}", since);

        int totalPublished = 0;

        // Query both ecosystems
        totalPublished += pollEcosystem("MAVEN", since);
        totalPublished += pollEcosystem("NPM", since);

        lastPollTimestamp.set(Instant.now());
        log.info("GitHub Advisory poll complete: published={}", totalPublished);
    }

    private int pollEcosystem(String ecosystem, Instant since) {
        String query = String.format(GRAPHQL_QUERY, ecosystem);
        String cursor = null;
        int published = 0;

        try {
            boolean hasNextPage;
            do {
                String updatedSince = DateTimeFormatter.ISO_INSTANT.format(since);

                Map<String, Object> variables = cursor != null
                        ? Map.of("updatedSince", updatedSince, "after", cursor)
                        : Map.of("updatedSince", updatedSince);

                Map<String, Object> requestBody = Map.of(
                        "query", query,
                        "variables", variables
                );

                JsonNode response = webClient.post()
                        .bodyValue(requestBody)
                        .retrieve()
                        .bodyToMono(JsonNode.class)
                        .block();

                if (response == null || response.has("errors")) {
                    log.warn("GitHub GraphQL returned errors for {}: {}",
                            ecosystem, response != null ? response.path("errors") : "null response");
                    break;
                }

                JsonNode advisories = response.path("data").path("securityAdvisories");
                JsonNode nodes = advisories.path("nodes");

                if (nodes.isArray()) {
                    for (JsonNode advisory : nodes) {
                        JsonNode adaptedAdvisory = adaptGraphQLAdvisory(advisory);
                        List<VulnerabilityEvent> events = normalizer.normalizeAdvisory(adaptedAdvisory);

                        for (VulnerabilityEvent event : events) {
                            if (!deduplicator.isDuplicate(EventSource.GITHUB, event.cveId())) {
                                publisher.publishVulnerability(event);
                                published++;
                            }
                        }
                    }
                }

                JsonNode pageInfo = advisories.path("pageInfo");
                hasNextPage = pageInfo.path("hasNextPage").asBoolean(false);
                cursor = pageInfo.path("endCursor").asText(null);

            } while (hasNextPage);

        } catch (Exception e) {
            log.error("GitHub Advisory poll failed for ecosystem {}", ecosystem, e);
        }

        return published;
    }

    /**
     * Adapts a GraphQL advisory node to match the format expected by
     * {@link GitHubAdvisoryNormalizer}.
     */
    private JsonNode adaptGraphQLAdvisory(JsonNode graphqlNode) {
        // The normalizer handles both webhook and GraphQL formats.
        // Map the GraphQL identifiers to cve_id/ghsa_id fields.
        if (graphqlNode.has("identifiers")) {
            var node = (com.fasterxml.jackson.databind.node.ObjectNode) graphqlNode;
            for (JsonNode identifier : graphqlNode.path("identifiers")) {
                String type = identifier.path("type").asText("");
                String value = identifier.path("value").asText("");
                if ("CVE".equals(type)) {
                    node.put("cve_id", value);
                } else if ("GHSA".equals(type)) {
                    node.put("ghsa_id", value);
                }
            }

            // Flatten vulnerabilities.nodes to match webhook structure
            JsonNode vulnNodes = graphqlNode.path("vulnerabilities").path("nodes");
            if (vulnNodes.isArray()) {
                node.set("vulnerabilities", vulnNodes);
            }

            // Flatten cvss.score
            double cvssScore = graphqlNode.path("cvss").path("score").asDouble(0.0);
            if (cvssScore > 0) {
                node.put("cvssScore", cvssScore);
            }

            // Map publishedAt
            String publishedAt = graphqlNode.path("publishedAt").asText(null);
            if (publishedAt != null) {
                node.put("published_at", publishedAt);
            }
        }

        return graphqlNode;
    }
}
