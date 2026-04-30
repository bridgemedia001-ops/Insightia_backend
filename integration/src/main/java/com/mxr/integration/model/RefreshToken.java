package com.mxr.integration.model;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import jakarta.persistence.Column;

import java.time.Instant;
import java.util.UUID;
import com.fasterxml.uuid.Generators;

@Entity
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "refresh_tokens")
public class RefreshToken {
    @Id
    UUID id;

    @PrePersist
    public void generateId() {
        this.id = Generators.timeBasedEpochGenerator().generate();
    }

    @Column(length = 512)
    private String token;

    private String username;

    private boolean isRevoked;

    private Instant expiresAt;

    private Instant createdAt;
}
