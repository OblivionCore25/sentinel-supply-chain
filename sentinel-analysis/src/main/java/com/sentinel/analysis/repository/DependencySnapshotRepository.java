package com.sentinel.analysis.repository;

import com.sentinel.analysis.entity.DependencySnapshotEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface DependencySnapshotRepository extends JpaRepository<DependencySnapshotEntity, UUID> {

    Optional<DependencySnapshotEntity> findTopByProjectIdOrderByResolvedAtDesc(UUID projectId);
}
