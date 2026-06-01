package com.sentinel.analysis.scoring;

import com.sentinel.analysis.graph.DependencyGraph;
import com.sentinel.analysis.graph.DependencyNode;
import com.sentinel.common.model.Ecosystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the multi-factor RiskScorer.
 */
class RiskScorerTest {

    private RiskScorer scorer;
    private DependencyGraph graph;

    @BeforeEach
    void setUp() {
        scorer = new RiskScorer(0.3, 365);

        // Build a test graph:
        // root:1.0 → lib-a:1.0 → vuln-pkg:1.0
        //           → lib-b:1.0 → vuln-pkg:1.0
        graph = new DependencyGraph();

        DependencyNode root = new DependencyNode("root", "1.0", Ecosystem.MAVEN, true);
        DependencyNode libA = new DependencyNode("lib-a", "1.0", Ecosystem.MAVEN, true);
        DependencyNode libB = new DependencyNode("lib-b", "1.0", Ecosystem.MAVEN, true);
        DependencyNode vulnPkg = new DependencyNode("vuln-pkg", "1.0", Ecosystem.MAVEN, false);
        vulnPkg.addVulnerability("CVE-2026-99999");

        graph.addNode(root);
        graph.addNode(libA);
        graph.addNode(libB);
        graph.addNode(vulnPkg);

        graph.addEdge("root:1.0", "lib-a:1.0");
        graph.addEdge("root:1.0", "lib-b:1.0");
        graph.addEdge("lib-a:1.0", "vuln-pkg:1.0");
        graph.addEdge("lib-b:1.0", "vuln-pkg:1.0");
    }

    @Test
    @DisplayName("Should compute positive score for reachable vulnerability")
    void scoringReachableVulnerability() {
        DependencyNode vulnNode = graph.getNode("vuln-pkg:1.0");
        Instant publishedRecently = Instant.now().minus(30, ChronoUnit.DAYS);

        RiskScorer.RiskResult result = scorer.score(
                graph, "root:1.0", vulnNode, "CVE-2026-99999", 9.8, publishedRecently);

        assertTrue(result.score() > 0, "Score should be positive for reachable vulnerability");
        assertEquals(2, result.transitiveDepth());
        assertEquals(2, result.pathCount()); // Two paths: via lib-a and lib-b
        assertEquals("CVE-2026-99999", result.cveId());
    }

    @Test
    @DisplayName("Should return zero score for unreachable vulnerability")
    void scoringUnreachableVulnerability() {
        DependencyNode isolated = new DependencyNode("isolated", "1.0", Ecosystem.MAVEN, false);
        graph.addNode(isolated);

        RiskScorer.RiskResult result = scorer.score(
                graph, "root:1.0", isolated, "CVE-0000-0000", 9.8, Instant.now());

        assertEquals(0.0, result.score());
        assertEquals(-1, result.transitiveDepth());
    }

    @Test
    @DisplayName("Direct dependency should have higher score than transitive")
    void directDependencyScoresHigher() {
        // Add a direct vulnerable dependency
        DependencyNode directVuln = new DependencyNode("direct-vuln", "1.0", Ecosystem.MAVEN, true);
        graph.addNode(directVuln);
        graph.addEdge("root:1.0", "direct-vuln:1.0");

        Instant published = Instant.now().minus(7, ChronoUnit.DAYS);

        RiskScorer.RiskResult directResult = scorer.score(
                graph, "root:1.0", directVuln, "CVE-DIRECT", 9.8, published);

        DependencyNode transitiveVuln = graph.getNode("vuln-pkg:1.0");
        RiskScorer.RiskResult transitiveResult = scorer.score(
                graph, "root:1.0", transitiveVuln, "CVE-TRANSITIVE", 9.8, published);

        assertTrue(directResult.score() > transitiveResult.score(),
                "Direct dependency score (" + directResult.score() +
                        ") should exceed transitive (" + transitiveResult.score() + ")");
    }

    @Test
    @DisplayName("Depth factor should decay for deeper dependencies")
    void depthFactorDecays() {
        assertEquals(1.0, scorer.calculateDepthFactor(1));
        assertTrue(scorer.calculateDepthFactor(2) < 1.0);
        assertTrue(scorer.calculateDepthFactor(5) < scorer.calculateDepthFactor(2));
        assertTrue(scorer.calculateDepthFactor(20) >= 0.1); // Never below 0.1
    }

    @Test
    @DisplayName("Fan-out factor should increase with more paths")
    void fanOutAmplifies() {
        assertEquals(1.0, scorer.calculateFanOutFactor(1));
        assertTrue(scorer.calculateFanOutFactor(2) > 1.0);
        assertTrue(scorer.calculateFanOutFactor(8) > scorer.calculateFanOutFactor(2));
        assertTrue(scorer.calculateFanOutFactor(1000) <= 1.5); // Capped at 1.5
    }

    @Test
    @DisplayName("Freshness factor should decay over time")
    void freshnessDecays() {
        assertEquals(1.0, scorer.calculateFreshnessFactor(Instant.now()));
        assertTrue(scorer.calculateFreshnessFactor(
                Instant.now().minus(180, ChronoUnit.DAYS)) < 1.0);
        assertTrue(scorer.calculateFreshnessFactor(
                Instant.now().minus(3650, ChronoUnit.DAYS)) >= 0.8); // Never below 0.8
    }

    @Test
    @DisplayName("Should batch-score multiple vulnerabilities")
    void batchScoring() {
        List<RiskScorer.VulnerabilityInput> vulns = List.of(
                new RiskScorer.VulnerabilityInput("CVE-2026-99999", "vuln-pkg", 9.8, Instant.now()),
                new RiskScorer.VulnerabilityInput("CVE-FAKE", "nonexistent-pkg", 5.0, Instant.now())
        );

        List<RiskScorer.RiskResult> results = scorer.scoreAll(graph, "root:1.0", vulns);

        // Only vuln-pkg should score (nonexistent-pkg isn't in the graph)
        assertEquals(1, results.size());
        assertEquals("CVE-2026-99999", results.get(0).cveId());
    }
}
