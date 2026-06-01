package com.sentinel.analysis.graph;

import com.sentinel.common.model.Ecosystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for the DependencyGraph data structure.
 * Tests graph operations used by the risk scorer.
 */
class DependencyGraphTest {

    private DependencyGraph graph;

    /**
     * Builds a test graph:
     * <pre>
     *   my-app:1.0.0
     *     ├─ lib-a:2.0.0
     *     │    └─ lib-c:1.0.0 (VULNERABLE)
     *     └─ lib-b:3.0.0
     *          └─ lib-c:1.0.0 (VULNERABLE)
     * </pre>
     */
    @BeforeEach
    void setUp() {
        graph = new DependencyGraph();

        DependencyNode root = new DependencyNode("my-app", "1.0.0", Ecosystem.MAVEN, true);
        DependencyNode libA = new DependencyNode("lib-a", "2.0.0", Ecosystem.MAVEN, true);
        DependencyNode libB = new DependencyNode("lib-b", "3.0.0", Ecosystem.MAVEN, true);
        DependencyNode libC = new DependencyNode("lib-c", "1.0.0", Ecosystem.MAVEN, false);
        libC.addVulnerability("CVE-2026-99999");

        graph.addNode(root);
        graph.addNode(libA);
        graph.addNode(libB);
        graph.addNode(libC);

        graph.addEdge("my-app:1.0.0", "lib-a:2.0.0");
        graph.addEdge("my-app:1.0.0", "lib-b:3.0.0");
        graph.addEdge("lib-a:2.0.0", "lib-c:1.0.0");
        graph.addEdge("lib-b:3.0.0", "lib-c:1.0.0");
    }

    @Test
    @DisplayName("Should report correct graph size")
    void correctSize() {
        assertEquals(4, graph.size());
        assertEquals(4, graph.edgeCount());
    }

    @Test
    @DisplayName("Should return correct direct dependencies")
    void directDependencies() {
        Set<String> deps = graph.getDependencies("my-app:1.0.0");
        assertEquals(Set.of("lib-a:2.0.0", "lib-b:3.0.0"), deps);
    }

    @Test
    @DisplayName("Should find minimum depth from root to transitive dependency")
    void minimumDepth() {
        assertEquals(0, graph.getMinDepth("my-app:1.0.0", "my-app:1.0.0"));
        assertEquals(1, graph.getMinDepth("my-app:1.0.0", "lib-a:2.0.0"));
        assertEquals(2, graph.getMinDepth("my-app:1.0.0", "lib-c:1.0.0"));
    }

    @Test
    @DisplayName("Should return -1 for unreachable nodes")
    void unreachableNode() {
        DependencyNode isolated = new DependencyNode("isolated", "1.0.0", Ecosystem.MAVEN, false);
        graph.addNode(isolated);
        assertEquals(-1, graph.getMinDepth("my-app:1.0.0", "isolated:1.0.0"));
    }

    @Test
    @DisplayName("Should find all paths (fan-out)")
    void allPaths() {
        List<List<String>> paths = graph.findAllPaths("my-app:1.0.0", "lib-c:1.0.0");
        assertEquals(2, paths.size()); // Two paths: via lib-a and via lib-b
    }

    @Test
    @DisplayName("Should compute correct path count")
    void pathCount() {
        assertEquals(2, graph.getPathCount("my-app:1.0.0", "lib-c:1.0.0"));
    }

    @Test
    @DisplayName("Should find transitive dependants")
    void transitiveDependants() {
        Set<String> dependants = graph.getTransitiveDependants("lib-c:1.0.0");
        assertTrue(dependants.contains("lib-a:2.0.0"));
        assertTrue(dependants.contains("lib-b:3.0.0"));
        assertTrue(dependants.contains("my-app:1.0.0"));
    }

    @Test
    @DisplayName("Should find nodes by package name")
    void findByPackageName() {
        List<DependencyNode> found = graph.findNodesByPackageName("lib-c");
        assertEquals(1, found.size());
        assertTrue(found.get(0).isVulnerable());
    }

    @Test
    @DisplayName("Should serialize to D3.js-compatible format")
    void serializableGraph() {
        DependencyGraph.GraphData data = graph.toSerializableGraph();
        assertEquals(4, data.nodes().size());
        assertEquals(4, data.edges().size());

        // Check that vulnerable node is marked
        var vulnNode = data.nodes().stream()
                .filter(n -> n.packageName().equals("lib-c"))
                .findFirst()
                .orElseThrow();
        assertTrue(vulnNode.vulnerable());
        assertTrue(vulnNode.vulnerabilities().contains("CVE-2026-99999"));
    }
}
