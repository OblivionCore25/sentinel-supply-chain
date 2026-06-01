package com.sentinel.notification.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the WebSocketSessionRegistry.
 */
class WebSocketSessionRegistryTest {

    private WebSocketSessionRegistry registry;

    @BeforeEach
    void setUp() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());
        registry = new WebSocketSessionRegistry(mapper);
    }

    @Test
    @DisplayName("Should start with zero active sessions")
    void startsEmpty() {
        assertEquals(0, registry.getActiveSessionCount());
    }

    @Test
    @DisplayName("Should not fail on broadcast with no sessions")
    void broadcastWithNoSessions() {
        assertDoesNotThrow(() ->
                registry.broadcast("TEST", Map.of("msg", "hello")));
    }

    @Test
    @DisplayName("Should handle unregister of non-existent session")
    void unregisterNonExistent() {
        assertDoesNotThrow(() -> registry.unregister("non-existent-id"));
        assertEquals(0, registry.getActiveSessionCount());
    }
}
