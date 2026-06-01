package com.sentinel.analysis.graph;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.common.model.Ecosystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Builds a {@link DependencyGraph} from resolved dependency tree JSON.
 * <p>
 * Supports dependency trees in a recursive format:
 * <pre>
 * {
 *   "name": "com.example:my-app",
 *   "version": "1.0.0",
 *   "ecosystem": "MAVEN",
 *   "dependencies": [
 *     {
 *       "name": "org.apache.logging.log4j:log4j-core",
 *       "version": "2.14.1",
 *       "dependencies": [...]
 *     }
 *   ]
 * }
 * </pre>
 */
@Component
public class GraphBuilder {

    private static final Logger log = LoggerFactory.getLogger(GraphBuilder.class);
    private final ObjectMapper objectMapper;

    public GraphBuilder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * Builds a dependency graph from a JSON dependency tree string.
     *
     * @param dependencyTreeJson JSON string of the resolved dependency tree
     * @param ecosystem          the package ecosystem
     * @return populated DependencyGraph
     */
    public DependencyGraph buildFromJson(String dependencyTreeJson, Ecosystem ecosystem) {
        DependencyGraph graph = new DependencyGraph();

        try {
            JsonNode tree = objectMapper.readTree(dependencyTreeJson);
            buildRecursive(graph, tree, null, ecosystem, true, 0);
        } catch (Exception e) {
            log.error("Failed to parse dependency tree JSON", e);
        }

        return graph;
    }

    /**
     * Builds a graph from a pre-parsed JsonNode.
     */
    public DependencyGraph buildFromJsonNode(JsonNode tree, Ecosystem ecosystem) {
        DependencyGraph graph = new DependencyGraph();
        buildRecursive(graph, tree, null, ecosystem, true, 0);
        return graph;
    }

    /**
     * Merges a dependency tree into an existing graph (for multi-project analysis).
     */
    public void mergeInto(DependencyGraph graph, String dependencyTreeJson, Ecosystem ecosystem) {
        try {
            JsonNode tree = objectMapper.readTree(dependencyTreeJson);
            buildRecursive(graph, tree, null, ecosystem, true, 0);
        } catch (Exception e) {
            log.error("Failed to merge dependency tree", e);
        }
    }

    private void buildRecursive(DependencyGraph graph, JsonNode node, String parentKey,
                                 Ecosystem ecosystem, boolean isDirect, int depth) {
        if (node == null || node.isMissingNode()) return;

        // Guard against unreasonably deep trees
        if (depth > 50) {
            log.warn("Dependency tree exceeds max depth of 50, truncating");
            return;
        }

        String name = node.path("name").asText(null);
        String version = node.path("version").asText("unknown");

        if (name == null || name.isBlank()) return;

        DependencyNode depNode = new DependencyNode(name, version, ecosystem, isDirect);
        String key = depNode.key();

        // Only add the node if it's not already in the graph
        if (graph.getNode(key) == null) {
            graph.addNode(depNode);
        }

        // Add edge from parent to this node
        if (parentKey != null) {
            graph.addEdge(parentKey, key);
        }

        // Recurse into dependencies
        JsonNode dependencies = node.path("dependencies");
        if (dependencies.isArray()) {
            for (JsonNode dep : dependencies) {
                buildRecursive(graph, dep, key, ecosystem, false, depth + 1);
            }
        }
    }
}
