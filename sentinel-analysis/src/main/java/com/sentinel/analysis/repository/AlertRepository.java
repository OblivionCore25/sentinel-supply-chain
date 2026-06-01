package com.sentinel.analysis.repository;

import com.sentinel.analysis.entity.AlertEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

@Repository
public interface AlertRepository extends JpaRepository<AlertEntity, UUID> {

    List<AlertEntity> findByProjectIdOrderByCreatedAtDesc(UUID projectId);

    List<AlertEntity> findByProjectIdAndAcknowledgedFalseOrderByCreatedAtDesc(UUID projectId);

    List<AlertEntity> findByAcknowledgedFalseOrderByCreatedAtDesc();

    long countByProjectIdAndAcknowledgedFalse(UUID projectId);
}
