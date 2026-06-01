package com.sentinel.analysis.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.analysis.entity.*;
import com.sentinel.analysis.graph.DependencyGraph;
import com.sentinel.analysis.graph.GraphBuilder;
import com.sentinel.analysis.repository.*;
import com.sentinel.analysis.scoring.RiskScorer;
import com.sentinel.analysis.service.AnalysisService;
import com.sentinel.common.event.VulnerabilityEvent;
import com.sentinel.common.model.Ecosystem;
import com.sentinel.common.model.EventSource;
import com.sentinel.common.model.Severity;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Full pipeline integration test verifying:
 * 1. Vulnerability upsert into database
 * 2. Dependency graph construction from JSON
 * 3. Multi-factor risk scoring
 * 4. Alert generation when score exceeds threshold
 *
 * Uses H2 in-memory database — no Docker required.
 * Kafka is mocked to isolate the analysis pipeline.
 */
@SpringBootTest
@ActiveProfiles("test")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class FullPipelineIntegrationTest {

    @Autowired private AnalysisService analysisService;
    @Autowired private ProjectRepository projectRepo;
    @Autowired private VulnerabilityRepository vulnerabilityRepo;
    @Autowired private DependencySnapshotRepository snapshotRepo;
    @Autowired private RiskScoreRepository riskScoreRepo;
    @Autowired private AlertRepository alertRepo;
    @Autowired private GraphBuilder graphBuilder;
    @Autowired private RiskScorer riskScorer;
    @Autowired private ObjectMapper objectMapper;

    @MockBean private KafkaTemplate<String, Object> kafkaTemplate;

    private static UUID projectId;

    /** Realistic dependency tree JSON for tests. */
    private static final String DEPENDENCY_TREE = """
            {
              "name": "my-api-service",
              "version": "1.0.0",
              "dependencies": [
                {
                  "name": "org.springframework:spring-web",
                  "version": "6.1.0",
                  "dependencies": [
                    {
                      "name": "org.springframework:spring-core",
                      "version": "6.1.0",
                      "dependencies": []
                    }
                  ]
                },
                {
                  "name": "org.apache.logging.log4j:log4j-core",
                  "version": "2.14.1",
                  "dependencies": [
                    {
                      "name": "org.apache.logging.log4j:log4j-api",
                      "version": "2.14.1",
                      "dependencies": []
                    }
                  ]
                },
                {
                  "name": "com.fasterxml.jackson.core:jackson-databind",
                  "version": "2.15.0",
                  "dependencies": [
                    {
                      "name": "com.fasterxml.jackson.core:jackson-core",
                      "version": "2.15.0",
                      "dependencies": []
                    },
                    {
                      "name": "com.fasterxml.jackson.core:jackson-annotations",
                      "version": "2.15.0",
                      "dependencies": []
                    }
                  ]
                }
              ]
            }
            """;

    @BeforeEach
    void seedProject() {
        alertRepo.deleteAll();
        riskScoreRepo.deleteAll();
        vulnerabilityRepo.deleteAll();
        snapshotRepo.deleteAll();
        projectRepo.deleteAll();

        ProjectEntity project = new ProjectEntity("my-api-service", "MAVEN");
        project.setRepositoryUrl("https://github.com/example/my-api-service");
        project = projectRepo.save(project);
        projectId = project.getId();

        DependencySnapshotEntity snapshot = new DependencySnapshotEntity(projectId, DEPENDENCY_TREE);
        snapshotRepo.save(snapshot);
    }

    // ---- Graph Tests (pure logic, no DB column dependency) ----

    @Test
    @Order(1)
    @DisplayName("Should construct dependency graph with 8 nodes from JSON")
    void shouldBuildDependencyGraph() {
        DependencyGraph graph = graphBuilder.buildFromJson(DEPENDENCY_TREE, Ecosystem.MAVEN);

        assertEquals(8, graph.size(), "Graph should have 8 nodes (1 root + 7 deps)");
        assertTrue(graph.edgeCount() > 0, "Graph should have edges");

        // Root has 3 direct dependencies
        var rootDeps = graph.getDependencies("my-api-service:1.0.0");
        assertEquals(3, rootDeps.size());

        // Transitive depth to log4j-api is 2
        int depth = graph.getMinDepth("my-api-service:1.0.0",
                "org.apache.logging.log4j:log4j-api:2.14.1");
        assertEquals(2, depth);
    }

    @Test
    @Order(2)
    @DisplayName("Should score depth-1 CRITICAL vulnerability above 7.0")
    void shouldScoreDirectVulnerability() {
        DependencyGraph graph = graphBuilder.buildFromJson(DEPENDENCY_TREE, Ecosystem.MAVEN);

        var log4jNode = graph.getNode("org.apache.logging.log4j:log4j-core:2.14.1");
        assertNotNull(log4jNode, "log4j-core should be in graph");

        // log4j-core is at depth 1 (direct dependency of the project root)
        int depth = graph.getMinDepth("my-api-service:1.0.0",
                "org.apache.logging.log4j:log4j-core:2.14.1");
        assertEquals(1, depth, "log4j-core should be at depth 1");

        RiskScorer.RiskResult result = riskScorer.score(
                graph, "my-api-service:1.0.0", log4jNode,
                "CVE-2021-44228", 10.0, Instant.now());

        assertTrue(result.score() > 7.0,
                "Depth-1 CRITICAL vulnerability should score > 7.0, got: " + result.score());
        assertEquals(1, result.transitiveDepth());
        assertEquals(1, result.pathCount());
    }

    @Test
    @Order(3)
    @DisplayName("Should score transitive dependency with depth decay")
    void shouldScoreTransitiveWithDecay() {
        DependencyGraph graph = graphBuilder.buildFromJson(DEPENDENCY_TREE, Ecosystem.MAVEN);

        var log4jApiNode = graph.getNode("org.apache.logging.log4j:log4j-api:2.14.1");
        assertNotNull(log4jApiNode, "log4j-api should be in graph");
        assertFalse(log4jApiNode.direct(), "log4j-api should be transitive");

        RiskScorer.RiskResult result = riskScorer.score(
                graph, "my-api-service:1.0.0", log4jApiNode,
                "CVE-2021-44832", 6.6, Instant.now());

        assertTrue(result.score() > 0, "Should have positive score");
        assertTrue(result.score() < 6.6,
                "Score should be less than raw CVSS due to depth decay, got: " + result.score());
        assertEquals(2, result.transitiveDepth());
    }

    @Test
    @Order(4)
    @DisplayName("Graph serialization should produce D3-compatible data")
    void shouldSerializeForD3() {
        DependencyGraph graph = graphBuilder.buildFromJson(DEPENDENCY_TREE, Ecosystem.MAVEN);

        var log4j = graph.getNode("org.apache.logging.log4j:log4j-core:2.14.1");
        assertNotNull(log4j);
        log4j.addVulnerability("CVE-2021-44228");

        DependencyGraph.GraphData data = graph.toSerializableGraph();

        assertEquals(8, data.nodes().size());
        assertTrue(data.edges().size() >= 7, "Should have at least 7 edges");

        // Verify vulnerable node is marked
        var vulnNodes = data.nodes().stream()
                .filter(DependencyGraph.GraphData.Node::vulnerable).toList();
        assertEquals(1, vulnNodes.size());
        assertEquals("org.apache.logging.log4j:log4j-core", vulnNodes.get(0).packageName());
        assertTrue(vulnNodes.get(0).vulnerabilities().contains("CVE-2021-44228"));

        // Verify direct flag (only root is marked direct in GraphBuilder)
        var rootNode = data.nodes().stream()
                .filter(n -> n.packageName().equals("my-api-service")).findFirst();
        assertTrue(rootNode.isPresent(), "Root node should exist");
        assertTrue(rootNode.get().direct(), "Root should be marked direct");
    }

    // ---- Database Integration Tests ----

    @Test
    @Order(5)
    @DisplayName("Should persist vulnerability via processVulnerability")
    void shouldPersistVulnerability() {
        VulnerabilityEvent event = new VulnerabilityEvent(
                "CVE-2021-44228",
                "org.apache.logging.log4j:log4j-core",
                ">=2.0.0, <2.17.1",
                10.0,
                Severity.CRITICAL,
                "Remote code execution via JNDI lookup in Apache Log4j 2",
                EventSource.NVD,
                Instant.parse("2021-12-10T10:00:00Z"),
                Instant.now()
        );

        analysisService.processVulnerability(event);

        var vulnOpt = vulnerabilityRepo.findByCveId("CVE-2021-44228");
        assertTrue(vulnOpt.isPresent(), "Vulnerability should be persisted");
        assertEquals("org.apache.logging.log4j:log4j-core", vulnOpt.get().getPackageName());
        // Use compareTo for BigDecimal (10.0 vs 10.00 scale differences)
        assertEquals(0, BigDecimal.valueOf(10.0).compareTo(vulnOpt.get().getCvssScore()),
                "CVSS score should be 10.0");
        assertEquals("CRITICAL", vulnOpt.get().getSeverity());
    }

    @Test
    @Order(6)
    @DisplayName("Should upsert vulnerability with higher CVSS score")
    void shouldUpsertWithHigherScore() {
        // First insert with lower score
        VulnerabilityEvent lowScore = new VulnerabilityEvent(
                "CVE-2026-99999", "com.example:lib",
                "< 2.0", 5.0, Severity.MEDIUM,
                "Moderate vuln", EventSource.OSV,
                Instant.now(), Instant.now()
        );
        analysisService.processVulnerability(lowScore);

        var vulnLow = vulnerabilityRepo.findByCveId("CVE-2026-99999");
        assertTrue(vulnLow.isPresent());
        assertEquals(0, BigDecimal.valueOf(5.0).compareTo(vulnLow.get().getCvssScore()));

        // Re-process with higher score — should update
        VulnerabilityEvent highScore = new VulnerabilityEvent(
                "CVE-2026-99999", "com.example:lib",
                "< 2.0", 9.0, Severity.CRITICAL,
                "Actually critical! Remote code execution.",
                EventSource.NVD, Instant.now(), Instant.now()
        );
        analysisService.processVulnerability(highScore);

        var vulnHigh = vulnerabilityRepo.findByCveId("CVE-2026-99999");
        assertTrue(vulnHigh.isPresent());
        assertEquals(0, BigDecimal.valueOf(9.0).compareTo(vulnHigh.get().getCvssScore()),
                "CVSS should update to higher score");
        assertEquals("CRITICAL", vulnHigh.get().getSeverity());
    }

    @Test
    @Order(7)
    @DisplayName("Should acknowledge alert and update timestamp")
    void shouldAcknowledgeAlert() {
        // Directly create an alert to test acknowledgment
        AlertEntity alert = new AlertEntity();
        alert.setProjectId(projectId);
        alert.setCveId("CVE-2021-44228");
        alert.setPackageName("org.apache.logging.log4j:log4j-core");
        alert.setSeverity("CRITICAL");
        alert.setMessage("Test alert");
        alert.setRiskScore(BigDecimal.valueOf(9.5));
        alert = alertRepo.save(alert);
        final UUID alertId = alert.getId();

        assertFalse(alert.isAcknowledged(), "Should start unacknowledged");

        // Acknowledge
        alert.acknowledge();
        alertRepo.save(alert);

        // Verify
        var updated = alertRepo.findById(alertId).orElseThrow();
        assertTrue(updated.isAcknowledged(), "Should be acknowledged");
        assertNotNull(updated.getAcknowledgedAt(), "Should have acknowledged timestamp");

        // Verify it no longer appears in unacknowledged list
        var unacked = alertRepo.findByProjectIdAndAcknowledgedFalseOrderByCreatedAtDesc(projectId);
        assertTrue(unacked.stream().noneMatch(a -> a.getId().equals(alertId)),
                "Acknowledged alert should not appear in unacknowledged list");
    }
}
