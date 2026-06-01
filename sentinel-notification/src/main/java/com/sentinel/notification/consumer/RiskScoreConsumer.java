package com.sentinel.notification.consumer;

import com.sentinel.common.event.RiskScoreEvent;
import com.sentinel.common.kafka.KafkaGroups;
import com.sentinel.common.kafka.KafkaTopics;
import com.sentinel.notification.cache.NotificationCacheService;
import com.sentinel.notification.websocket.WebSocketSessionRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * Kafka consumer for risk score events from the Analysis Service.
 * <p>
 * On each event:
 * 1. Caches the score in Redis for fast dashboard access
 * 2. Broadcasts to all connected WebSocket sessions
 */
@Component
public class RiskScoreConsumer {

    private static final Logger log = LoggerFactory.getLogger(RiskScoreConsumer.class);

    private final NotificationCacheService cacheService;
    private final WebSocketSessionRegistry webSocketRegistry;

    public RiskScoreConsumer(NotificationCacheService cacheService,
                              WebSocketSessionRegistry webSocketRegistry) {
        this.cacheService = cacheService;
        this.webSocketRegistry = webSocketRegistry;
    }

    @KafkaListener(
            topics = KafkaTopics.RISK_SCORES,
            groupId = KafkaGroups.NOTIFICATION,
            containerFactory = "kafkaListenerContainerFactory"
    )
    public void onRiskScore(RiskScoreEvent event) {
        log.info("Received risk score: project={}, cve={}, score={}",
                event.projectId(), event.cveId(), String.format("%.2f", event.score()));

        // 1. Cache in Redis
        cacheService.cacheRiskScore(event)
                .subscribe(
                        null,
                        err -> log.error("Failed to cache risk score", err)
                );

        // 2. Push to WebSocket clients
        webSocketRegistry.broadcast("RISK_SCORE", event);
    }
}
