package com.mxr.integration.repo;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.mxr.integration.model.User;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByGithubId(String githubId);

    Optional<User> findByUsername(String username);

    boolean existsByGithubId(String githubId);
}
