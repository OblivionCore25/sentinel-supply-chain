package com.sentinel.common.kafka;

/**
 * Kafka consumer group ID constants.
 * Each consumer group gets its own offset tracking.
 */
public final class KafkaGroups {

    private KafkaGroups() {
        // utility class
    }

    /** Analysis service — vulnerability events */
    public static final String ANALYSIS_VULN = "analysis-vuln-group";

    /** Analysis service — dependency and package events */
    public static final String ANALYSIS_DEPENDENCY = "analysis-dependency-group";

    /** Notification service — risk scores and alerts */
    public static final String NOTIFICATION = "notification-group";
}
