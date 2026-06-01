package com.sentinel.analysis.service;

import com.sentinel.analysis.entity.*;
import com.sentinel.analysis.graph.DependencyGraph;
import com.sentinel.analysis.graph.DependencyNode;
import com.sentinel.analysis.graph.GraphBuilder;
import com.sentinel.analysis.repository.*;
import com.sentinel.analysis.scoring.RiskScorer;
import com.sentinel.common.event.AlertEvent;
import com.sentinel.common.event.RiskScoreEvent;
import com.sentinel.common.event.VulnerabilityEvent;
import com.sentinel.common.kafka.KafkaTopics;
import com.sentinel.common.model.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Core analysis orchestrator that ties together vulnerability storage,
 * dependency graph resolution, risk scoring, and alert generation.
 */
@Service
public class AnalysisService {

    private static final Logger log = LoggerFactory.getLogger(AnalysisService.class);

    private final VulnerabilityRepository vulnerabilityRepo;
    private final ProjectRepository projectRepo;
    private final DependencySnapshotRepository snapshotRepo;
    private final RiskScoreRepository riskScoreRepo;
    private final AlertRepository alertRepo;
    private final GraphBuilder graphBuilder;
    private final RiskScorer riskScorer;
    private final KafkaTemplate<String, Object> kafkaTemplate;
    private final double alertThreshold;

    public AnalysisService(
            VulnerabilityRepository vulnerabilityRepo,
            ProjectRepository projectRepo,
            DependencySnapshotRepository snapshotRepo,
            RiskScoreRepository riskScoreRepo,
            AlertRepository alertRepo,
            GraphBuilder graphBuilder,
            RiskScorer riskScorer,
            KafkaTemplate<String, Object> kafkaTemplate,
            @Value("${sentinel.analysis.scoring.alert-threshold:7.0}") double alertThreshold) {
        this.vulnerabilityRepo = vulnerabilityRepo;
        this.projectRepo = projectRepo;
        this.snapshotRepo = snapshotRepo;
        this.riskScoreRepo = riskScoreRepo;
        this.alertRepo = alertRepo;
        this.graphBuilder = graphBuilder;
        this.riskScorer = riskScorer;
        this.kafkaTemplate = kafkaTemplate;
        this.alertThreshold = alertThreshold;
    }

    /**
     * Processes a new vulnerability event:
     * 1. Upserts the vulnerability in the database
     * 2. Finds all affected projects
     * 3. Re-scores each project
     * 4. Publishes risk scores and alerts
     */
    @Transactional
    public void processVulnerability(VulnerabilityEvent event) {
        log.info("Processing vulnerability: cveId={}, package={}", event.cveId(), event.packageName());

        // 1. Upsert vulnerability
        VulnerabilityEntity vulnEntity = upsertVulnerability(event);

        // 2. Find all projects and re-score them
        List<ProjectEntity> allProjects = projectRepo.findAll();
        for (ProjectEntity project : allProjects) {
            rescoreProjectForVulnerability(project, vulnEntity, event);
        }
    }

    /**
     * Re-scores all known vulnerabilities for a specific project.
     * Called when a project's dependency tree changes.
     */
    @Transactional
    public void rescoreProject(ProjectEntity project) {
        log.info("Re-scoring project: {}", project.getName());

        List<VulnerabilityEntity> allVulns = vulnerabilityRepo.findAll();
        for (VulnerabilityEntity vuln : allVulns) {
            rescoreProjectForVulnerability(project, vuln, null);
        }
    }

    /**
     * Scores a specific project against a specific vulnerability.
     */
    private void rescoreProjectForVulnerability(ProjectEntity project,
                                                 VulnerabilityEntity vulnEntity,
                                                 VulnerabilityEvent event) {
        // Load the latest dependency snapshot
        Optional<DependencySnapshotEntity> snapshotOpt =
                snapshotRepo.findTopByProjectIdOrderByResolvedAtDesc(project.getId());

        if (snapshotOpt.isEmpty()) {
            log.debug("No dependency snapshot for project {}, skipping scoring", project.getName());
            return;
        }

        DependencySnapshotEntity snapshot = snapshotOpt.get();

        // Build the dependency graph
        var ecosystem = com.sentinel.common.model.Ecosystem.valueOf(project.getEcosystem());
        DependencyGraph graph = graphBuilder.buildFromJson(snapshot.getDependencyTree(), ecosystem);

        // Find the root node (project itself)
        String rootKey = project.getName() + ":latest";
        if (graph.getNode(rootKey) == null) {
            // Try to find by project name alone
            var candidates = graph.findNodesByPackageName(project.getName());
            if (candidates.isEmpty()) {
                log.debug("Project root node not found in graph for {}", project.getName());
                return;
            }
            rootKey = candidates.get(0).key();
        }

        // Check if the vulnerability affects any package in the graph
        List<DependencyNode> affectedNodes = graph.findNodesByPackageName(vulnEntity.getPackageName());
        if (affectedNodes.isEmpty()) {
            return; // This vulnerability doesn't affect this project
        }

        // Mark nodes as vulnerable
        for (DependencyNode node : affectedNodes) {
            node.addVulnerability(vulnEntity.getCveId());
        }

        // Score each affected node
        double cvss = vulnEntity.getCvssScore() != null
                ? vulnEntity.getCvssScore().doubleValue()
                : (event != null ? event.cvssScore() : 5.0);

        Instant publishedAt = vulnEntity.getPublishedAt() != null
                ? vulnEntity.getPublishedAt()
                : (event != null ? event.publishedAt() : Instant.now());

        for (DependencyNode node : affectedNodes) {
            RiskScorer.RiskResult result = riskScorer.score(
                    graph, rootKey, node, vulnEntity.getCveId(), cvss, publishedAt);

            if (result.score() > 0) {
                persistAndPublishScore(project, vulnEntity, result);
            }
        }
    }

    /**
     * Persists a risk score, publishes it to Kafka, and creates an alert if needed.
     */
    private void persistAndPublishScore(ProjectEntity project,
                                         VulnerabilityEntity vulnEntity,
                                         RiskScorer.RiskResult result) {
        // Persist to database
        RiskScoreEntity scoreEntity = new RiskScoreEntity();
        scoreEntity.setProjectId(project.getId());
        scoreEntity.setVulnerabilityId(vulnEntity.getId());
        scoreEntity.setCveId(result.cveId());
        scoreEntity.setScore(BigDecimal.valueOf(result.score()));
        scoreEntity.setTransitiveDepth(result.transitiveDepth());
        scoreEntity.setPathCount(result.pathCount());
        riskScoreRepo.save(scoreEntity);

        // Publish risk score event to Kafka
        RiskScoreEvent scoreEvent = new RiskScoreEvent(
                project.getId().toString(),
                project.getName(),
                vulnEntity.getId().toString(),
                result.cveId(),
                result.score(),
                result.transitiveDepth(),
                result.pathCount(),
                result.affectedPath(),
                Instant.now()
        );
        kafkaTemplate.send(KafkaTopics.RISK_SCORES, project.getId().toString(), scoreEvent);

        log.info("Risk score computed: project={}, cve={}, score={}",
                project.getName(), result.cveId(), String.format("%.2f", result.score()));

        // Generate alert if score exceeds threshold
        if (result.score() >= alertThreshold) {
            generateAlert(project, vulnEntity, result);
        }
    }

    /**
     * Creates an alert and publishes it to Kafka.
     */
    private void generateAlert(ProjectEntity project,
                                VulnerabilityEntity vulnEntity,
                                RiskScorer.RiskResult result) {
        Severity severity = Severity.fromCvss(result.score());

        // Persist alert
        AlertEntity alertEntity = new AlertEntity();
        alertEntity.setProjectId(project.getId());
        alertEntity.setVulnerabilityId(vulnEntity.getId());
        alertEntity.setCveId(result.cveId());
        alertEntity.setPackageName(vulnEntity.getPackageName());
        alertEntity.setSeverity(severity.name());
        alertEntity.setMessage(String.format(
                "High-risk vulnerability %s (score %.1f) affects %s via %s at depth %d",
                result.cveId(), result.score(), project.getName(),
                vulnEntity.getPackageName(), result.transitiveDepth()));
        alertEntity.setRiskScore(BigDecimal.valueOf(result.score()));
        alertRepo.save(alertEntity);

        // Publish alert event
        AlertEvent alertEvent = new AlertEvent(
                project.getId().toString(),
                project.getName(),
                result.cveId(),
                vulnEntity.getPackageName(),
                severity,
                alertEntity.getMessage(),
                result.score(),
                Instant.now()
        );
        kafkaTemplate.send(KafkaTopics.RISK_ALERTS, project.getId().toString(), alertEvent);

        log.warn("ALERT generated: project={}, cve={}, score={}, severity={}",
                project.getName(), result.cveId(), result.score(), severity);
    }

    /**
     * Upserts a vulnerability from an ingestion event.
     */
    private VulnerabilityEntity upsertVulnerability(VulnerabilityEvent event) {
        return vulnerabilityRepo.findByCveId(event.cveId())
                .map(existing -> {
                    // Update if CVSS score increased or description is more detailed
                    if (event.cvssScore() > existing.getCvssScore().doubleValue()) {
                        existing.setCvssScore(BigDecimal.valueOf(event.cvssScore()));
                        existing.setSeverity(event.severity().name());
                    }
                    if (event.description() != null && (existing.getDescription() == null
                            || event.description().length() > existing.getDescription().length())) {
                        existing.setDescription(event.description());
                    }
                    return vulnerabilityRepo.save(existing);
                })
                .orElseGet(() -> {
                    VulnerabilityEntity entity = new VulnerabilityEntity();
                    entity.setCveId(event.cveId());
                    entity.setPackageName(event.packageName());
                    entity.setAffectedRange(event.affectedRange());
                    entity.setCvssScore(BigDecimal.valueOf(event.cvssScore()));
                    entity.setSeverity(event.severity().name());
                    entity.setDescription(event.description());
                    entity.setPublishedAt(event.publishedAt());
                    entity.setSource(event.source().name());
                    return vulnerabilityRepo.save(entity);
                });
    }
}
