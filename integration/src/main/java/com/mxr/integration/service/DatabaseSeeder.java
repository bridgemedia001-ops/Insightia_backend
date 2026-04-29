package com.mxr.integration.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mxr.integration.model.Person;
import com.mxr.integration.repo.PersonRepoImpl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
public class DatabaseSeeder implements CommandLineRunner {

    @Autowired
    private PersonRepoImpl personRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void run(String... args) throws Exception {
        if (shouldSeed()) {
            seedDatabase();
        }
    }

    private boolean shouldSeed() {
        // Check if database is empty
        return personRepository.count() == 0;
    }

    public void seedDatabase() {
        try {
            log.info("Starting database seeding...");

            List<Person> profiles = loadProfilesFromJson();
            int savedCount = 0;
            int skippedCount = 0;

            for (Person profile : profiles) {
                // Check if profile already exists by name (case-insensitive)
                if (!personRepository.existsByName(profile.getName())) {
                    personRepository.save(profile);
                    savedCount++;
                    log.debug("Saved profile: {}", profile.getName());
                } else {
                    skippedCount++;
                    log.debug("Skipped duplicate profile: {}", profile.getName());
                }
            }

            log.info("Database seeding completed. Saved: {}, Skipped: {}", savedCount, skippedCount);

        } catch (Exception e) {
            log.error("Error seeding database", e);
        }
    }

    private List<Person> loadProfilesFromJson() throws IOException {
        List<Person> profiles = new ArrayList<>();

        try (InputStream inputStream = new ClassPathResource("seed_profiles.json").getInputStream()) {
            JsonNode rootNode = objectMapper.readTree(inputStream);
            JsonNode profilesNode = rootNode.get("profiles");

            if (profilesNode != null && profilesNode.isArray()) {
                for (JsonNode profileNode : profilesNode) {
                    Person person = Person.builder()
                            .name(profileNode.get("name").asText())
                            .gender(profileNode.get("gender").asText())
                            .genderProbability(profileNode.get("gender_probability").asDouble())
                            .age(profileNode.get("age").asInt())
                            .ageGroup(profileNode.get("age_group").asText())
                            .countryId(profileNode.get("country_id").asText())
                            .countryName(profileNode.get("country_name").asText())
                            .countryProbability(profileNode.get("country_probability").asDouble())
                            .build();

                    profiles.add(person);
                }
            }
        }

        return profiles;
    }
}
