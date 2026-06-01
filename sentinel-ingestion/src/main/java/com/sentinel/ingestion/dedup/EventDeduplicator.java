package com.sentinel.ingestion.dedup;

import com.sentinel.common.model.EventSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

/**
 * Redis-backed event deduplication.
 * <p>
 * Uses Redis SETNX with a configurable TTL to prevent reprocessing
 * of the same event from multiple sources or duplicate webhook deliveries.
 * <p>
 * Key format: {@code sentinel:dedup:{source}:{sourceId}}
 */
@Component
public class EventDeduplicator {

    private static final Logger log = LoggerFactory.getLogger(EventDeduplicator.class);
    private static final String KEY_PREFIX = "sentinel:dedup:";

    private final StringRedisTemplate redisTemplate;
    private final Duration ttl;

    public EventDeduplicator(
            StringRedisTemplate redisTemplate,
            @Value("${sentinel.ingestion.dedup.ttl:PT24H}") Duration ttl) {
        this.redisTemplate = redisTemplate;
        this.ttl = ttl;
    }

    /**
     * Checks if an event has already been processed.
     *
     * @param source   the data source (NVD, OSV, GITHUB, etc.)
     * @param sourceId the source-specific unique identifier (e.g., CVE ID, advisory GHSA ID)
     * @return true if the event is a duplicate (already seen within the TTL window)
     */
    public boolean isDuplicate(EventSource source, String sourceId) {
        String key = buildKey(source, sourceId);
        Boolean wasAbsent = redisTemplate.opsForValue().setIfAbsent(key, "1", ttl);

        if (wasAbsent == null || !wasAbsent) {
            log.debug("Duplicate event detected: source={}, id={}", source, sourceId);
            return true;
        }

        log.debug("New event accepted: source={}, id={}", source, sourceId);
        return false;
    }

    /**
     * Manually marks an event as processed (useful for manual ingest endpoints).
     */
    public void markProcessed(EventSource source, String sourceId) {
        String key = buildKey(source, sourceId);
        redisTemplate.opsForValue().set(key, "1", ttl);
    }

    /**
     * Clears dedup state for a specific event (useful for reprocessing).
     */
    public void clear(EventSource source, String sourceId) {
        String key = buildKey(source, sourceId);
        redisTemplate.delete(key);
    }

    private String buildKey(EventSource source, String sourceId) {
        return KEY_PREFIX + source.name() + ":" + sourceId;
    }
}
