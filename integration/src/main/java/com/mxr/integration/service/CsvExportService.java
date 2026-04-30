package com.mxr.integration.service;

import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import com.mxr.integration.model.Person;
import com.mxr.integration.repo.PersonRepoImpl;
import com.mxr.integration.spec.PersonSpecification;

@Service
public class CsvExportService {

    private final PersonRepoImpl repo;
    

    public CsvExportService(PersonRepoImpl repo) {
        this.repo = repo;
    }

    public byte[] exportToCsv(String gender, String countryId, String ageGroup, Integer minimumAge,
            Integer maximumAge, Double minCountryProbability, Double minGenderProbability, String sortBy,
            String order) {

        Specification<Person> spec = Specification
                .where(PersonSpecification.hasGender(gender))
                .and(PersonSpecification.hasCountryId(countryId))
                .and(PersonSpecification.hasAgeGroup(ageGroup))
                .and(PersonSpecification.greaterThanAge(minimumAge))
                .and(PersonSpecification.lessThanAge(maximumAge))
                .and(PersonSpecification.greaterThanCountryProbability(minCountryProbability))
                .and(PersonSpecification.greaterThanGenderProbability(minGenderProbability));

        Sort.Direction direction = Sort.Direction.fromString(order);
        String javaField = IntegrationService.mapSortField(sortBy);
        Pageable pageable = PageRequest.of(0, 10000, Sort.by(direction, javaField));
        Page<Person> result = repo.findAll(spec, pageable);

        return generateCsv(result.getContent());
    }

    private byte[] generateCsv(List<Person> profiles) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PrintWriter writer = new PrintWriter(outputStream, true, StandardCharsets.UTF_8);

        writer.println(
                "id,name,gender,gender_probability,age,age_group,country_id,country_name,country_probability,created_at");

        for (Person profile : profiles) {
            writer.println(String.format("%s,%s,%s,%.2f,%d,%s,%s,%s,%.2f,%s",
                    profile.getId(),
                    escapeCsv(profile.getName()),
                    escapeCsv(profile.getGender()),
                    profile.getGenderProbability(),
                    profile.getAge(),
                    escapeCsv(profile.getAgeGroup()),
                    escapeCsv(profile.getCountryId()),
                    escapeCsv(profile.getCountryName()),
                    profile.getCountryProbability(),
                    profile.getCreatedAt()));
        }

        writer.flush();
        return outputStream.toByteArray();
    }

    private String escapeCsv(String value) {
        if (value == null) {
            return "";
        }
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
