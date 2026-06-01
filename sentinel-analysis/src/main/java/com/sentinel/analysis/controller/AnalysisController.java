package com.sentinel.analysis.controller;

import com.sentinel.analysis.entity.*;
import com.sentinel.analysis.graph.DependencyGraph;
import com.sentinel.analysis.graph.GraphBuilder;
import com.sentinel.analysis.repository.*;
import com.sentinel.common.model.Ecosystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * REST API for the React dashboard and D3.js graph visualization.
 * Provides project management, risk scores, alerts, and graph data.
 */
@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "*") // Dashboard CORS — restricted in production
public class AnalysisController {

    private static final Logger log = LoggerFactory.getLogger(AnalysisController.class);

    private final ProjectRepository projectRepo;
    private final VulnerabilityRepository vulnerabilityRepo;
    private final RiskScoreRepository riskScoreRepo;
    private final AlertRepository alertRepo;
    private final DependencySnapshotRepository snapshotRepo;
    private final GraphBuilder graphBuilder;

    public AnalysisController(ProjectRepository projectRepo,
                               VulnerabilityRepository vulnerabilityRepo,
                               RiskScoreRepository riskScoreRepo,
                               AlertRepository alertRepo,
                               DependencySnapshotRepository snapshotRepo,
                               GraphBuilder graphBuilder) {
        this.projectRepo = projectRepo;
        this.vulnerabilityRepo = vulnerabilityRepo;
        this.riskScoreRepo = riskScoreRepo;
        this.alertRepo = alertRepo;
        this.snapshotRepo = snapshotRepo;
        this.graphBuilder = graphBuilder;
    }

    // ========================
    //  Projects
    // ========================

    @GetMapping("/projects")
    public List<ProjectEntity> getAllProjects() {
        return projectRepo.findAll();
    }

    @GetMapping("/projects/{id}")
    public ResponseEntity<ProjectEntity> getProject(@PathVariable UUID id) {
        return projectRepo.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/projects")
    public ResponseEntity<ProjectEntity> createProject(@RequestBody CreateProjectRequest request) {
        if (projectRepo.existsByName(request.name())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }

        ProjectEntity project = new ProjectEntity(request.name(), request.ecosystem());
        project.setRepositoryUrl(request.repositoryUrl());
        project.setManifestPath(request.manifestPath());
        return ResponseEntity.status(HttpStatus.CREATED).body(projectRepo.save(project));
    }

    // ========================
    //  Risk Scores
    // ========================

    @GetMapping("/projects/{id}/risk-scores")
    public ResponseEntity<List<RiskScoreEntity>> getProjectRiskScores(@PathVariable UUID id) {
        if (!projectRepo.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(riskScoreRepo.findLatestScoresByProjectId(id));
    }

    @GetMapping("/projects/{id}/risk-scores/history")
    public ResponseEntity<List<RiskScoreEntity>> getRiskScoreHistory(@PathVariable UUID id) {
        if (!projectRepo.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(riskScoreRepo.findByProjectIdOrderByScoredAtDesc(id));
    }

    // ========================
    //  Alerts
    // ========================

    @GetMapping("/alerts")
    public List<AlertEntity> getAllUnacknowledgedAlerts() {
        return alertRepo.findByAcknowledgedFalseOrderByCreatedAtDesc();
    }

    @GetMapping("/projects/{id}/alerts")
    public ResponseEntity<List<AlertEntity>> getProjectAlerts(@PathVariable UUID id) {
        if (!projectRepo.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(alertRepo.findByProjectIdAndAcknowledgedFalseOrderByCreatedAtDesc(id));
    }

    @PostMapping("/alerts/{id}/acknowledge")
    public ResponseEntity<AlertEntity> acknowledgeAlert(@PathVariable UUID id) {
        return alertRepo.findById(id)
                .map(alert -> {
                    alert.acknowledge();
                    return ResponseEntity.ok(alertRepo.save(alert));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    // ========================
    //  Vulnerabilities
    // ========================

    @GetMapping("/vulnerabilities")
    public List<VulnerabilityEntity> getAllVulnerabilities() {
        return vulnerabilityRepo.findAll();
    }

    @GetMapping("/vulnerabilities/{cveId}")
    public ResponseEntity<VulnerabilityEntity> getVulnerability(@PathVariable String cveId) {
        return vulnerabilityRepo.findByCveId(cveId)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    // ========================
    //  Dependency Graph (D3.js)
    // ========================

    @GetMapping("/projects/{id}/graph")
    public ResponseEntity<DependencyGraph.GraphData> getProjectGraph(@PathVariable UUID id) {
        Optional<ProjectEntity> projectOpt = projectRepo.findById(id);
        if (projectOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        ProjectEntity project = projectOpt.get();
        Optional<DependencySnapshotEntity> snapshotOpt =
                snapshotRepo.findTopByProjectIdOrderByResolvedAtDesc(id);

        if (snapshotOpt.isEmpty()) {
            return ResponseEntity.ok(new DependencyGraph.GraphData(List.of(), List.of()));
        }

        Ecosystem ecosystem = Ecosystem.valueOf(project.getEcosystem());
        DependencyGraph graph = graphBuilder.buildFromJson(
                snapshotOpt.get().getDependencyTree(), ecosystem);

        // Mark known vulnerabilities on the graph
        List<VulnerabilityEntity> vulns = vulnerabilityRepo.findAll();
        for (VulnerabilityEntity vuln : vulns) {
            graph.findNodesByPackageName(vuln.getPackageName())
                    .forEach(node -> node.addVulnerability(vuln.getCveId()));
        }

        return ResponseEntity.ok(graph.toSerializableGraph());
    }

    // ========================
    //  Dashboard Summary
    // ========================

    @GetMapping("/dashboard/summary")
    public Map<String, Object> getDashboardSummary() {
        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalProjects", projectRepo.count());
        summary.put("totalVulnerabilities", vulnerabilityRepo.count());
        summary.put("unacknowledgedAlerts", alertRepo.findByAcknowledgedFalseOrderByCreatedAtDesc().size());

        // Per-project alert counts
        List<Map<String, Object>> projectAlerts = new ArrayList<>();
        for (ProjectEntity project : projectRepo.findAll()) {
            long unacked = alertRepo.countByProjectIdAndAcknowledgedFalse(project.getId());
            projectAlerts.add(Map.of(
                    "projectId", project.getId(),
                    "projectName", project.getName(),
                    "unacknowledgedAlerts", unacked
            ));
        }
        summary.put("projects", projectAlerts);

        return summary;
    }

    // ========================
    //  Request DTOs
    // ========================

    public record CreateProjectRequest(
            String name,
            String ecosystem,
            String repositoryUrl,
            String manifestPath
    ) {}
}
