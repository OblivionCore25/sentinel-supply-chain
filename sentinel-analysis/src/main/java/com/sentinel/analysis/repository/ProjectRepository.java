package com.sentinel.analysis.repository;

import com.sentinel.analysis.entity.ProjectEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ProjectRepository extends JpaRepository<ProjectEntity, UUID> {

    Optional<ProjectEntity> findByName(String name);

    List<ProjectEntity> findByEcosystem(String ecosystem);

    boolean existsByName(String name);
}
