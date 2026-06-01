package com.sentinel.notification.consumer;

import com.sentinel.common.event.AlertEvent;
import com.sentinel.common.kafka.KafkaGroups;
import com.sentinel.common.kafka.KafkaTopics;
import com.sentinel.notification.cache.NotificationCacheService;
import com.sentinel.notification.websocket.WebSocketSessionRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * Kafka consumer for alert events from the Analysis Service.
 * <p>
 * On each event:
 * 1. Caches the alert in Redis
 * 2. Broadcasts to all connected WebSocket sessions with ALERT type
 */
@Component
public class AlertConsumer {

    private static final Logger log = LoggerFactory.getLogger(AlertConsumer.class);

    private final NotificationCacheService cacheService;
    private final WebSocketSessionRegistry webSocketRegistry;

    public AlertConsumer(NotificationCacheService cacheService,
                          WebSocketSessionRegistry webSocketRegistry) {
        this.cacheService = cacheService;
        this.webSocketRegistry = webSocketRegistry;
    }

    @KafkaListener(
            topics = KafkaTopics.RISK_ALERTS,
            groupId = KafkaGroups.NOTIFICATION,
            containerFactory = "kafkaListenerContainerFactory"
    )
    public void onAlert(AlertEvent event) {
        log.warn("ALERT received: project={}, cve={}, severity={}, score={}",
                event.projectId(), event.cveId(), event.severity(),
                String.format("%.2f", event.riskScore()));

        // 1. Cache in Redis
        cacheService.cacheAlert(event)
                .subscribe(
                        null,
                        err -> log.error("Failed to cache alert", err)
                );

        // 2. Push to WebSocket clients
        webSocketRegistry.broadcast("ALERT", event);
    }
}
