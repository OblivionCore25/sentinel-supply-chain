package com.sentinel.analysis.consumer;

import com.sentinel.analysis.entity.DependencySnapshotEntity;
import com.sentinel.analysis.entity.ProjectEntity;
import com.sentinel.analysis.repository.DependencySnapshotRepository;
import com.sentinel.analysis.repository.ProjectRepository;
import com.sentinel.analysis.service.AnalysisService;
import com.sentinel.common.event.DependencyUpdateEvent;
import com.sentinel.common.kafka.KafkaGroups;
import com.sentinel.common.kafka.KafkaTopics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * Kafka consumer for dependency update events.
 * When a project's dependencies change, re-resolve the graph and re-score.
 */
@Component
public class DependencyUpdateConsumer {

    private static final Logger log = LoggerFactory.getLogger(DependencyUpdateConsumer.class);

    private final ProjectRepository projectRepo;
    private final AnalysisService analysisService;

    public DependencyUpdateConsumer(ProjectRepository projectRepo,
                                    AnalysisService analysisService) {
        this.projectRepo = projectRepo;
        this.analysisService = analysisService;
    }

    @KafkaListener(
            topics = KafkaTopics.DEPENDENCY_UPDATED,
            groupId = KafkaGroups.ANALYSIS_DEPENDENCY,
            containerFactory = "kafkaListenerContainerFactory"
    )
    public void onDependencyUpdated(DependencyUpdateEvent event) {
        log.info("Received dependency update: project={}, package={}, {} -> {}",
                event.projectId(), event.packageName(),
                event.previousVersion(), event.newVersion());

        try {
            Optional<ProjectEntity> projectOpt = projectRepo.findByName(event.projectId());

            if (projectOpt.isEmpty()) {
                log.debug("Project not found: {}, skipping re-score", event.projectId());
                return;
            }

            analysisService.rescoreProject(projectOpt.get());

        } catch (Exception e) {
            log.error("Failed to process dependency update: project={}",
                    event.projectId(), e);
            throw e;
        }
    }
}
