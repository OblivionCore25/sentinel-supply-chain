package com.sentinel.notification.websocket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.socket.WebSocketHandler;
import org.springframework.web.reactive.socket.WebSocketSession;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Reactive WebSocket handler for the dashboard real-time feed.
 * <p>
 * Protocol:
 * <ul>
 *   <li>On connect: sends a CONNECTION event with session info</li>
 *   <li>Server-push: RISK_SCORE and ALERT events broadcast from Kafka consumers</li>
 *   <li>Client messages: currently ignored (future: subscribe to specific projects)</li>
 * </ul>
 * <p>
 * Message format (JSON):
 * <pre>
 * {
 *   "type": "RISK_SCORE" | "ALERT" | "CONNECTION",
 *   "payload": { ... }
 * }
 * </pre>
 */
@Component
public class DashboardWebSocketHandler implements WebSocketHandler {

    private static final Logger log = LoggerFactory.getLogger(DashboardWebSocketHandler.class);

    private final WebSocketSessionRegistry registry;

    public DashboardWebSocketHandler(WebSocketSessionRegistry registry) {
        this.registry = registry;
    }

    @Override
    public Mono<Void> handle(WebSocketSession session) {
        log.info("Dashboard WebSocket connection: id={}, uri={}",
                session.getId(), session.getHandshakeInfo().getUri());

        // Send welcome message immediately
        registry.broadcast("CONNECTION", Map.of(
                "sessionId", session.getId(),
                "message", "Connected to Sentinel real-time feed",
                "activeSessions", registry.getActiveSessionCount() + 1
        ));

        // Register session and get the outbound message flux
        var outbound = registry.register(session)
                .map(session::textMessage);

        // Consume inbound messages (currently just log them)
        var inbound = session.receive()
                .doOnNext(msg -> log.debug("Received from client {}: {}",
                        session.getId(), msg.getPayloadAsText()))
                .doOnError(err -> log.warn("WebSocket error for {}: {}",
                        session.getId(), err.getMessage()))
                .doFinally(signal -> {
                    log.info("WebSocket session {} closed: {}", session.getId(), signal);
                    registry.unregister(session.getId());
                })
                .then();

        // Run both inbound and outbound streams concurrently
        return Mono.zip(session.send(outbound), inbound).then();
    }
}
