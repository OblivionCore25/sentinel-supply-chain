package com.sentinel.common.model;

/**
 * Sources of vulnerability and advisory data.
 */
public enum EventSource {
    /** NIST National Vulnerability Database */
    NVD,
    /** Open Source Vulnerabilities (Google) */
    OSV,
    /** GitHub Advisory Database */
    GITHUB,
    /** Manually injected (testing/demo) */
    MANUAL
}
