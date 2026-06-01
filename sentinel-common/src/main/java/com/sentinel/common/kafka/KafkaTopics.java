package com.sentinel.common.kafka;

/**
 * Kafka topic name constants.
 * Centralized here to ensure consistency across producer and consumer services.
 */
public final class KafkaTopics {

    private KafkaTopics() {
        // utility class
    }

    // --- Ingestion topics (produced by Ingestion Service) ---

    /** New vulnerability disclosures. Key: CVE ID */
    public static final String VULN_DISCLOSED = "vuln.disclosed";

    /** Dependency version updates for monitored projects. Key: package name */
    public static final String DEPENDENCY_UPDATED = "dependency.updated";

    /** New package version releases. Key: package name */
    public static final String PACKAGE_RELEASED = "package.released";

    // --- Risk topics (produced by Analysis Service) ---

    /** Computed risk scores per project. Key: project ID */
    public static final String RISK_SCORES = "risk.scores";

    /** High-severity alerts. Key: project ID */
    public static final String RISK_ALERTS = "risk.alerts";

    /** Dead letter queue for failed analysis. Key: original key */
    public static final String RISK_SCORES_DLQ = "risk.scores.dlq";
}
