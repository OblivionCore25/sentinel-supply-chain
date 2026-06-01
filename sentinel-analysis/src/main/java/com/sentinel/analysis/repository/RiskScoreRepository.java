package com.sentinel.analysis.repository;

import com.sentinel.analysis.entity.RiskScoreEntity;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface RiskScoreRepository extends JpaRepository<RiskScoreEntity, UUID> {

    List<RiskScoreEntity> findByProjectIdOrderByScoredAtDesc(UUID projectId, Pageable pageable);

    List<RiskScoreEntity> findByProjectIdOrderByScoredAtDesc(UUID projectId);

    @Query("SELECT r FROM RiskScoreEntity r WHERE r.projectId = :projectId " +
           "AND r.scoredAt = (SELECT MAX(r2.scoredAt) FROM RiskScoreEntity r2 WHERE r2.projectId = :projectId AND r2.cveId = r.cveId)")
    List<RiskScoreEntity> findLatestScoresByProjectId(UUID projectId);

    List<RiskScoreEntity> findByCveId(String cveId);
}
