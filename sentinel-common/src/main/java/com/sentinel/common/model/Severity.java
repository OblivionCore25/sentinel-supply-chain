package com.sentinel.common.model;

/**
 * Severity levels for vulnerabilities and alerts.
 * Ordered from most to least severe.
 */
public enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW;

    /**
     * Derives severity from a CVSS score using standard ranges.
     */
    public static Severity fromCvss(double cvssScore) {
        if (cvssScore >= 9.0) return CRITICAL;
        if (cvssScore >= 7.0) return HIGH;
        if (cvssScore >= 4.0) return MEDIUM;
        return LOW;
    }
}
