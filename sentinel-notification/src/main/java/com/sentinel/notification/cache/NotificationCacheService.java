package com.sentinel.notification.cache;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.common.event.AlertEvent;
import com.sentinel.common.event.RiskScoreEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;

/**
 * Redis-backed cache for the most recent risk scores and alerts.
 * <p>
 * Provides a fast-access layer for the dashboard REST endpoints so the
 * React frontend doesn't need to query the Analysis Service's database.
 * <p>
 * Cache keys:
 * <ul>
 *   <li>{@code sentinel:scores:recent} — last 50 risk scores (list)</li>
 *   <li>{@code sentinel:alerts:recent} — last 50 alerts (list)</li>
 *   <li>{@code sentinel:scores:project:{projectId}} — latest score per project (string)</li>
 * </ul>
 */
@Service
public class NotificationCacheService {

    private static final Logger log = LoggerFactory.getLogger(NotificationCacheService.class);

    private static final String RECENT_SCORES_KEY = "sentinel:scores:recent";
    private static final String RECENT_ALERTS_KEY = "sentinel:alerts:recent";
    private static final String PROJECT_SCORE_PREFIX = "sentinel:scores:project:";
    private static final long MAX_RECENT_ENTRIES = 50;
    private static final Duration CACHE_TTL = Duration.ofHours(24);

    private final ReactiveStringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public NotificationCacheService(ReactiveStringRedisTemplate redisTemplate,
                                     ObjectMapper objectMapper) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    /**
     * Caches a risk score event.
     */
    public Mono<Void> cacheRiskScore(RiskScoreEvent event) {
        return serialize(event)
                .flatMap(json -> {
                    // Push to recent scores list
                    Mono<Long> push = redisTemplate.opsForList()
                            .leftPush(RECENT_SCORES_KEY, json);

                    // Trim to last N entries
                    Mono<Void> trim = redisTemplate.opsForList()
                            .trim(RECENT_SCORES_KEY, 0, MAX_RECENT_ENTRIES - 1)
                            .then();

                    // Set TTL
                    Mono<Boolean> expire = redisTemplate.expire(RECENT_SCORES_KEY, CACHE_TTL);

                    // Cache per-project latest score
                    String projectKey = PROJECT_SCORE_PREFIX + event.projectId();
                    Mono<Boolean> projectCache = redisTemplate.opsForValue()
                            .set(projectKey, json, CACHE_TTL);

                    return Mono.when(push, trim, expire, projectCache);
                })
                .doOnError(e -> log.error("Failed to cache risk score: {}", e.getMessage()))
                .onErrorResume(e -> Mono.empty());
    }

    /**
     * Caches an alert event.
     */
    public Mono<Void> cacheAlert(AlertEvent event) {
        return serialize(event)
                .flatMap(json -> {
                    Mono<Long> push = redisTemplate.opsForList()
                            .leftPush(RECENT_ALERTS_KEY, json);

                    Mono<Void> trim = redisTemplate.opsForList()
                            .trim(RECENT_ALERTS_KEY, 0, MAX_RECENT_ENTRIES - 1)
                            .then();

                    Mono<Boolean> expire = redisTemplate.expire(RECENT_ALERTS_KEY, CACHE_TTL);

                    return Mono.when(push, trim, expire);
                })
                .doOnError(e -> log.error("Failed to cache alert: {}", e.getMessage()))
                .onErrorResume(e -> Mono.empty());
    }

    /**
     * Retrieves the most recent risk scores.
     */
    public Flux<RiskScoreEvent> getRecentScores(long count) {
        return redisTemplate.opsForList()
                .range(RECENT_SCORES_KEY, 0, count - 1)
                .flatMap(json -> deserialize(json, RiskScoreEvent.class));
    }

    /**
     * Retrieves the most recent alerts.
     */
    public Flux<AlertEvent> getRecentAlerts(long count) {
        return redisTemplate.opsForList()
                .range(RECENT_ALERTS_KEY, 0, count - 1)
                .flatMap(json -> deserialize(json, AlertEvent.class));
    }

    /**
     * Retrieves the latest risk score for a specific project.
     */
    public Mono<RiskScoreEvent> getLatestProjectScore(String projectId) {
        String key = PROJECT_SCORE_PREFIX + projectId;
        return redisTemplate.opsForValue()
                .get(key)
                .flatMap(json -> deserialize(json, RiskScoreEvent.class));
    }

    private Mono<String> serialize(Object obj) {
        return Mono.fromCallable(() -> objectMapper.writeValueAsString(obj));
    }

    private <T> Mono<T> deserialize(String json, Class<T> type) {
        return Mono.fromCallable(() -> objectMapper.readValue(json, type))
                .onErrorResume(e -> {
                    log.warn("Failed to deserialize cached entry: {}", e.getMessage());
                    return Mono.empty();
                });
    }
}
