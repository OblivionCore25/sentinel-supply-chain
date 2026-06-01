package com.sentinel.analysis.scoring;

import com.sentinel.analysis.graph.DependencyGraph;
import com.sentinel.analysis.graph.DependencyNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Multi-factor risk scoring engine for supply chain vulnerabilities.
 * <p>
 * Computes a composite risk score based on:
 * <ol>
 *   <li><strong>CVSS Base Score</strong> — the vulnerability's inherent severity (0–10)</li>
 *   <li><strong>Transitive Depth Decay</strong> — deeper transitive deps are less immediately exploitable</li>
 *   <li><strong>Fan-Out Amplifier</strong> — more paths to the vulnerable dep = higher exposure</li>
 *   <li><strong>Freshness Decay</strong> — older vulnerabilities with no action are slightly penalized</li>
 *   <li><strong>Direct Dependency Boost</strong> — direct deps get a 1.2x multiplier</li>
 * </ol>
 * <p>
 * Formula:
 * <pre>
 *   score = cvss × depthFactor × fanOutFactor × freshnessFactor × directBoost
 * </pre>
 * Where:
 * <pre>
 *   depthFactor   = 1 / (1 + depthDecay × (minDepth - 1))  [clamped to 0.1]
 *   fanOutFactor  = 1 + log2(pathCount) × 0.1               [capped at 1.5]
 *   freshness     = 1 - (daysSincePublished / freshnessWindow) × 0.2 [clamped to 0.8]
 *   directBoost   = 1.2 if direct, 1.0 otherwise
 * </pre>
 */
@Component
public class RiskScorer {

    private static final Logger log = LoggerFactory.getLogger(RiskScorer.class);

    private final double depthDecayFactor;
    private final int freshnessWindowDays;

    public RiskScorer(
            @Value("${sentinel.analysis.scoring.depth-decay-factor:0.3}") double depthDecayFactor,
            @Value("${sentinel.analysis.scoring.freshness-window-days:365}") int freshnessWindowDays) {
        this.depthDecayFactor = depthDecayFactor;
        this.freshnessWindowDays = freshnessWindowDays;
    }

    /**
     * Scores a specific vulnerability against a project's dependency graph.
     *
     * @param graph       the project's resolved dependency graph
     * @param rootNodeKey the root node key (the project itself)
     * @param vulnNode    the vulnerable dependency node
     * @param cveId       the CVE identifier
     * @param cvssScore   the raw CVSS score of the vulnerability
     * @param publishedAt when the vulnerability was published (for freshness)
     * @return computed RiskResult
     */
    public RiskResult score(DependencyGraph graph, String rootNodeKey,
                            DependencyNode vulnNode, String cveId,
                            double cvssScore, Instant publishedAt) {

        String vulnKey = vulnNode.key();

        // 1. Transitive depth
        int minDepth = graph.getMinDepth(rootNodeKey, vulnKey);
        if (minDepth < 0) {
            log.debug("No path from {} to {} — vulnerability not reachable", rootNodeKey, vulnKey);
            return new RiskResult(cveId, vulnKey, 0.0, -1, 0, List.of());
        }

        // 2. Path count (fan-out)
        int pathCount = graph.getPathCount(rootNodeKey, vulnKey);

        // 3. Collect affected dependency path
        List<String> affectedPath = collectAffectedPath(graph, rootNodeKey, vulnKey);

        // 4. Calculate composite score
        double depthFactor = calculateDepthFactor(minDepth);
        double fanOutFactor = calculateFanOutFactor(pathCount);
        double freshnessFactor = calculateFreshnessFactor(publishedAt);
        double directBoost = vulnNode.direct() ? 1.2 : 1.0;

        double compositeScore = cvssScore * depthFactor * fanOutFactor * freshnessFactor * directBoost;

        // Clamp to 0–10 range
        compositeScore = Math.min(10.0, Math.max(0.0, compositeScore));

        log.debug("Risk score for {} via {}: base={}, depth={}(f={}), paths={}(f={}), fresh={}, direct={} → {}",
                cveId, vulnKey, cvssScore, minDepth, depthFactor, pathCount, fanOutFactor,
                freshnessFactor, directBoost, compositeScore);

        return new RiskResult(cveId, vulnKey, compositeScore, minDepth, pathCount, affectedPath);
    }

    /**
     * Scores all known vulnerabilities against a project graph.
     */
    public List<RiskResult> scoreAll(DependencyGraph graph, String rootNodeKey,
                                     List<VulnerabilityInput> vulnerabilities) {
        List<RiskResult> results = new ArrayList<>();

        for (VulnerabilityInput vuln : vulnerabilities) {
            List<DependencyNode> affectedNodes = graph.findNodesByPackageName(vuln.packageName());

            for (DependencyNode node : affectedNodes) {
                RiskResult result = score(graph, rootNodeKey, node, vuln.cveId(),
                        vuln.cvssScore(), vuln.publishedAt());
                if (result.score() > 0) {
                    results.add(result);
                }
            }
        }

        return results;
    }

    // --- Factor Calculations ---

    /**
     * Depth decay: direct deps (depth=1) get full weight; deeper deps decay.
     * Formula: 1 / (1 + decay × (depth - 1)), clamped to [0.1, 1.0]
     */
    double calculateDepthFactor(int minDepth) {
        if (minDepth <= 1) return 1.0;
        double factor = 1.0 / (1.0 + depthDecayFactor * (minDepth - 1));
        return Math.max(0.1, factor);
    }

    /**
     * Fan-out amplifier: more paths = more exposure.
     * Formula: 1 + log2(pathCount) × 0.1, capped at 1.5
     */
    double calculateFanOutFactor(int pathCount) {
        if (pathCount <= 1) return 1.0;
        double factor = 1.0 + (Math.log(pathCount) / Math.log(2)) * 0.1;
        return Math.min(1.5, factor);
    }

    /**
     * Freshness decay: older unpatched vulnerabilities are slightly penalized.
     * Formula: 1 - (daysSince / window) × 0.2, clamped to [0.8, 1.0]
     */
    double calculateFreshnessFactor(Instant publishedAt) {
        if (publishedAt == null) return 1.0;
        long daysSince = Duration.between(publishedAt, Instant.now()).toDays();
        if (daysSince <= 0) return 1.0;
        double factor = 1.0 - ((double) daysSince / freshnessWindowDays) * 0.2;
        return Math.max(0.8, Math.min(1.0, factor));
    }

    /**
     * Collects the shortest path from root to the vulnerable node.
     */
    private List<String> collectAffectedPath(DependencyGraph graph, String rootKey, String vulnKey) {
        var allPaths = graph.findAllPaths(rootKey, vulnKey);
        if (allPaths.isEmpty()) return List.of();

        // Return the shortest path
        return allPaths.stream()
                .min((a, b) -> Integer.compare(a.size(), b.size()))
                .orElse(List.of());
    }

    // --- Supporting records ---

    /**
     * Result of a risk score computation.
     */
    public record RiskResult(
            String cveId,
            String vulnerableNodeKey,
            double score,
            int transitiveDepth,
            int pathCount,
            List<String> affectedPath
    ) {}

    /**
     * Input record for batch scoring.
     */
    public record VulnerabilityInput(
            String cveId,
            String packageName,
            double cvssScore,
            Instant publishedAt
    ) {}
}
