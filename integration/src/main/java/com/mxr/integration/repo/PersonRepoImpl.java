package com.mxr.integration.repo;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;
import com.mxr.integration.model.Person;

@Repository
public interface PersonRepoImpl extends JpaRepository<Person, UUID>, JpaSpecificationExecutor<Person> {
    Optional<Person> findByNameIgnoreCase(String name);

    Page<Person> findByNameContaining(String name, Pageable pageable);

    void deleteByName(String name);

    Person findByName(String name);

    Optional<Person> findById(UUID id);

    boolean existsByName(String name);
}
