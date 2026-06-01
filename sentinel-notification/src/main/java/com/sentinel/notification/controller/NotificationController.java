package com.sentinel.notification.controller;

import com.sentinel.common.event.AlertEvent;
import com.sentinel.common.event.RiskScoreEvent;
import com.sentinel.notification.cache.NotificationCacheService;
import com.sentinel.notification.websocket.WebSocketSessionRegistry;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * REST endpoints for the Notification Service.
 * <p>
 * Provides cached recent events for the dashboard initial load,
 * complementing the real-time WebSocket feed.
 */
@RestController
@RequestMapping("/api/notifications")
public class NotificationController {

    private final NotificationCacheService cacheService;
    private final WebSocketSessionRegistry sessionRegistry;

    public NotificationController(NotificationCacheService cacheService,
                                   WebSocketSessionRegistry sessionRegistry) {
        this.cacheService = cacheService;
        this.sessionRegistry = sessionRegistry;
    }

    /**
     * Returns the most recent risk scores (cached in Redis).
     * Used by the dashboard for initial page load before WebSocket events arrive.
     */
    @GetMapping("/scores/recent")
    public Flux<RiskScoreEvent> getRecentScores(
            @RequestParam(defaultValue = "20") long count) {
        return cacheService.getRecentScores(Math.min(count, 50));
    }

    /**
     * Returns the most recent alerts (cached in Redis).
     */
    @GetMapping("/alerts/recent")
    public Flux<AlertEvent> getRecentAlerts(
            @RequestParam(defaultValue = "20") long count) {
        return cacheService.getRecentAlerts(Math.min(count, 50));
    }

    /**
     * Returns the latest risk score for a specific project.
     */
    @GetMapping("/scores/project/{projectId}")
    public Mono<RiskScoreEvent> getProjectScore(@PathVariable String projectId) {
        return cacheService.getLatestProjectScore(projectId);
    }

    /**
     * Health/status endpoint for the Notification Service.
     */
    @GetMapping("/status")
    public Mono<Map<String, Object>> getStatus() {
        return Mono.just(Map.of(
                "service", "sentinel-notification",
                "status", "UP",
                "activeWebSockets", sessionRegistry.getActiveSessionCount()
        ));
    }
}
