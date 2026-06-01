package com.sentinel.notification.websocket;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.socket.WebSocketSession;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages active WebSocket sessions and broadcasts events to all connected clients.
 * <p>
 * Uses Reactor Sinks for non-blocking, backpressure-aware fan-out.
 * Each connected dashboard session receives real-time risk score and alert events.
 */
@Component
public class WebSocketSessionRegistry {

    private static final Logger log = LoggerFactory.getLogger(WebSocketSessionRegistry.class);

    private final Map<String, Sinks.Many<String>> sessionSinks = new ConcurrentHashMap<>();
    private final ObjectMapper objectMapper;

    public WebSocketSessionRegistry(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Registers a new WebSocket session and returns a Flux of messages for it.
     */
    public Flux<String> register(WebSocketSession session) {
        String sessionId = session.getId();
        Sinks.Many<String> sink = Sinks.many().multicast().onBackpressureBuffer(256);
        sessionSinks.put(sessionId, sink);

        log.info("WebSocket session connected: id={}, total={}", sessionId, sessionSinks.size());

        // Clean up when the session ends
        return sink.asFlux()
                .doOnCancel(() -> unregister(sessionId))
                .doOnTerminate(() -> unregister(sessionId));
    }

    /**
     * Unregisters a WebSocket session.
     */
    public void unregister(String sessionId) {
        Sinks.Many<String> sink = sessionSinks.remove(sessionId);
        if (sink != null) {
            sink.tryEmitComplete();
            log.info("WebSocket session disconnected: id={}, remaining={}", sessionId, sessionSinks.size());
        }
    }

    /**
     * Broadcasts a message to all connected sessions.
     *
     * @param eventType the event type (e.g., "RISK_SCORE", "ALERT")
     * @param payload   the event payload object (will be JSON-serialized)
     */
    public void broadcast(String eventType, Object payload) {
        if (sessionSinks.isEmpty()) {
            log.debug("No active WebSocket sessions, skipping broadcast");
            return;
        }

        try {
            WebSocketMessage message = new WebSocketMessage(eventType, payload);
            String json = objectMapper.writeValueAsString(message);

            int sent = 0;
            for (Map.Entry<String, Sinks.Many<String>> entry : sessionSinks.entrySet()) {
                Sinks.EmitResult result = entry.getValue().tryEmitNext(json);
                if (result.isSuccess()) {
                    sent++;
                } else {
                    log.warn("Failed to send to session {}: {}", entry.getKey(), result);
                }
            }

            log.debug("Broadcast {} event to {}/{} sessions", eventType, sent, sessionSinks.size());

        } catch (JsonProcessingException e) {
            log.error("Failed to serialize WebSocket message", e);
        }
    }

    /**
     * Returns the count of active sessions.
     */
    public int getActiveSessionCount() {
        return sessionSinks.size();
    }

    /**
     * Envelope for WebSocket messages sent to clients.
     *
     * @param type    event type identifier (RISK_SCORE, ALERT, CONNECTION)
     * @param payload the event data
     */
    public record WebSocketMessage(String type, Object payload) {}
}
