package com.sentinel.analysis.graph;

import com.sentinel.common.model.Ecosystem;

import java.util.HashSet;
import java.util.Set;

/**
 * Represents a single node in the dependency graph.
 *
 * @param packageName         fully qualified package identifier (e.g., "org.apache.logging.log4j:log4j-core")
 * @param version             resolved version
 * @param ecosystem           package ecosystem (MAVEN or NPM)
 * @param direct              true if this is a direct dependency of a project
 * @param knownVulnerabilities set of CVE IDs affecting this package version
 */
public record DependencyNode(
        String packageName,
        String version,
        Ecosystem ecosystem,
        boolean direct,
        Set<String> knownVulnerabilities
) {
    public DependencyNode(String packageName, String version, Ecosystem ecosystem, boolean direct) {
        this(packageName, version, ecosystem, direct, new HashSet<>());
    }

    /**
     * Unique key for graph identity: "packageName:version".
     */
    public String key() {
        return packageName + ":" + version;
    }

    public boolean isVulnerable() {
        return knownVulnerabilities != null && !knownVulnerabilities.isEmpty();
    }

    public void addVulnerability(String cveId) {
        knownVulnerabilities.add(cveId);
    }
}
