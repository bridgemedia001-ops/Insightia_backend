package com.mxr.integration.model;

import jakarta.persistence.Entity;

import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.time.Instant;

import java.util.UUID;
import com.fasterxml.uuid.Generators;
import org.hibernate.annotations.CreationTimestamp;
import com.fasterxml.jackson.annotation.JsonProperty;

@Entity
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor

@Table(name = "profiles")
public class Person {
    @Id
    UUID id;
    
    @PrePersist
    public void generateId() {
        this.id = Generators.timeBasedEpochGenerator().generate();
    }
    
    @NotNull
    private String name;

    @NotNull
    private String gender;

    @JsonProperty("gender_probability")
    private double genderProbability;

    @JsonProperty("country_name")
    private String countryName;

    private int age;

    @JsonProperty("age_group")
    private String ageGroup;

    @JsonProperty("country_id")
    private String countryId;

    @JsonProperty("country_probability")
    private double countryProbability;

    @JsonProperty("created_at")
    @CreationTimestamp
    private Instant createdAt;


    
}
