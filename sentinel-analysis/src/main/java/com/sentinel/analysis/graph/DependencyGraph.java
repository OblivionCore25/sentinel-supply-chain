package com.sentinel.analysis.graph;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Directed acyclic graph (DAG) representing a dependency tree.
 * <p>
 * Edges point from dependant → dependency (i.e., "A depends on B" = edge A→B).
 * To find all projects affected by a vulnerability, we walk edges in reverse.
 * <p>
 * This class provides key operations needed by the risk scorer:
 * <ul>
 *   <li>{@link #getTransitiveDependants(String)} — all nodes that transitively depend on a package</li>
 *   <li>{@link #findAllPaths(String, String)} — all distinct paths between two nodes</li>
 *   <li>{@link #getMinDepth(String, String)} — shortest path depth (BFS)</li>
 *   <li>{@link #getPathCount(String, String)} — total number of distinct paths (for fan-out scoring)</li>
 * </ul>
 */
public class DependencyGraph {

    /** Forward adjacency: node → set of nodes it depends on */
    private final Map<String, Set<String>> forwardEdges = new HashMap<>();

    /** Reverse adjacency: node → set of nodes that depend on it */
    private final Map<String, Set<String>> reverseEdges = new HashMap<>();

    /** Node metadata indexed by key */
    private final Map<String, DependencyNode> nodes = new HashMap<>();

    /**
     * Adds a node to the graph.
     */
    public void addNode(DependencyNode node) {
        nodes.put(node.key(), node);
        forwardEdges.computeIfAbsent(node.key(), k -> new HashSet<>());
        reverseEdges.computeIfAbsent(node.key(), k -> new HashSet<>());
    }

    /**
     * Adds a directed edge: {@code from} depends on {@code to}.
     */
    public void addEdge(String fromKey, String toKey) {
        forwardEdges.computeIfAbsent(fromKey, k -> new HashSet<>()).add(toKey);
        reverseEdges.computeIfAbsent(toKey, k -> new HashSet<>()).add(fromKey);
    }

    /**
     * Returns the node for a given key, or null if not found.
     */
    public DependencyNode getNode(String key) {
        return nodes.get(key);
    }

    /**
     * Returns all nodes in the graph.
     */
    public Collection<DependencyNode> getAllNodes() {
        return Collections.unmodifiableCollection(nodes.values());
    }

    /**
     * Returns all node keys.
     */
    public Set<String> getAllNodeKeys() {
        return Collections.unmodifiableSet(nodes.keySet());
    }

    /**
     * Returns the direct dependencies of a node (forward edges).
     */
    public Set<String> getDependencies(String nodeKey) {
        return Collections.unmodifiableSet(forwardEdges.getOrDefault(nodeKey, Set.of()));
    }

    /**
     * Returns all nodes that directly depend on the given node (reverse edges).
     */
    public Set<String> getDirectDependants(String nodeKey) {
        return Collections.unmodifiableSet(reverseEdges.getOrDefault(nodeKey, Set.of()));
    }

    /**
     * Returns all nodes that transitively depend on the given package.
     * Walks reverse edges using BFS.
     *
     * @param nodeKey the node to find dependants of
     * @return set of all transitively dependent node keys
     */
    public Set<String> getTransitiveDependants(String nodeKey) {
        Set<String> visited = new HashSet<>();
        Queue<String> queue = new LinkedList<>();
        queue.add(nodeKey);

        while (!queue.isEmpty()) {
            String current = queue.poll();
            Set<String> dependants = reverseEdges.getOrDefault(current, Set.of());
            for (String dependant : dependants) {
                if (visited.add(dependant)) {
                    queue.add(dependant);
                }
            }
        }

        return visited;
    }

    /**
     * Finds all distinct paths from {@code fromKey} to {@code toKey}.
     * Uses DFS with path tracking.
     *
     * @return list of paths, where each path is a list of node keys
     */
    public List<List<String>> findAllPaths(String fromKey, String toKey) {
        List<List<String>> allPaths = new ArrayList<>();
        List<String> currentPath = new ArrayList<>();
        Set<String> visited = new HashSet<>();

        currentPath.add(fromKey);
        visited.add(fromKey);
        dfsAllPaths(fromKey, toKey, currentPath, visited, allPaths);

        return allPaths;
    }

    private void dfsAllPaths(String current, String target,
                             List<String> currentPath, Set<String> visited,
                             List<List<String>> allPaths) {
        if (current.equals(target)) {
            allPaths.add(new ArrayList<>(currentPath));
            return;
        }

        // Cap at 100 paths to prevent combinatorial explosion
        if (allPaths.size() >= 100) return;

        for (String neighbor : forwardEdges.getOrDefault(current, Set.of())) {
            if (!visited.contains(neighbor)) {
                visited.add(neighbor);
                currentPath.add(neighbor);
                dfsAllPaths(neighbor, target, currentPath, visited, allPaths);
                currentPath.remove(currentPath.size() - 1);
                visited.remove(neighbor);
            }
        }
    }

    /**
     * Returns the minimum depth (shortest path length) from {@code fromKey} to {@code toKey}.
     * Uses BFS for O(V+E) performance.
     *
     * @return shortest path depth, or -1 if no path exists
     */
    public int getMinDepth(String fromKey, String toKey) {
        if (fromKey.equals(toKey)) return 0;

        Map<String, Integer> distances = new HashMap<>();
        Queue<String> queue = new LinkedList<>();
        distances.put(fromKey, 0);
        queue.add(fromKey);

        while (!queue.isEmpty()) {
            String current = queue.poll();
            int depth = distances.get(current);

            for (String neighbor : forwardEdges.getOrDefault(current, Set.of())) {
                if (!distances.containsKey(neighbor)) {
                    distances.put(neighbor, depth + 1);
                    if (neighbor.equals(toKey)) {
                        return depth + 1;
                    }
                    queue.add(neighbor);
                }
            }
        }

        return -1; // No path exists
    }

    /**
     * Returns the total number of distinct paths from {@code fromKey} to {@code toKey}.
     * This is the "fan-out" metric used in risk scoring.
     */
    public int getPathCount(String fromKey, String toKey) {
        return findAllPaths(fromKey, toKey).size();
    }

    /**
     * Returns all nodes that match a package name (ignoring version).
     */
    public List<DependencyNode> findNodesByPackageName(String packageName) {
        return nodes.values().stream()
                .filter(n -> n.packageName().equals(packageName))
                .collect(Collectors.toList());
    }

    /**
     * Returns the total number of nodes in the graph.
     */
    public int size() {
        return nodes.size();
    }

    /**
     * Returns the total number of edges in the graph.
     */
    public int edgeCount() {
        return forwardEdges.values().stream().mapToInt(Set::size).sum();
    }

    /**
     * Exports the graph as a serializable structure for the D3.js dashboard.
     */
    public GraphData toSerializableGraph() {
        List<GraphData.Node> exportNodes = nodes.values().stream()
                .map(n -> new GraphData.Node(
                        n.key(), n.packageName(), n.version(),
                        n.ecosystem().name(), n.direct(), n.isVulnerable(),
                        n.knownVulnerabilities()))
                .toList();

        List<GraphData.Edge> exportEdges = new ArrayList<>();
        forwardEdges.forEach((from, tos) -> {
            for (String to : tos) {
                exportEdges.add(new GraphData.Edge(from, to));
            }
        });

        return new GraphData(exportNodes, exportEdges);
    }

    /**
     * Serializable graph structure for the dashboard API.
     */
    public record GraphData(List<Node> nodes, List<Edge> edges) {
        public record Node(String id, String packageName, String version,
                           String ecosystem, boolean direct, boolean vulnerable,
                           Set<String> vulnerabilities) {}
        public record Edge(String source, String target) {}
    }
}
