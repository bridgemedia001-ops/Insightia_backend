package com.mxr.integration.controller;

import org.springframework.web.bind.annotation.RestController;

import com.mxr.integration.Response.PersonExistsResponse;
import com.mxr.integration.Response.ProcessedResponse;
import com.mxr.integration.Response.ProfilePageResponse;
import com.mxr.integration.model.Person;
import com.mxr.integration.request.NewEntityRequest;
import com.mxr.integration.service.IntegrationService;
import com.mxr.integration.service.DatabaseSeeder;
import com.mxr.integration.service.CsvExportService;
import com.mxr.integration.queryparser.NaturalQueryParser;
import com.mxr.integration.queryparser.ParsedQuery;
import com.mxr.integration.exceptions.InvalidQueryParametersException;
import com.mxr.integration.exceptions.UninterpretableQueryException;
import com.mxr.integration.security.RequireRole;
import com.mxr.integration.security.Role;

import jakarta.validation.Valid;

import java.util.Map;

import java.util.UUID;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

@RestController
public class classifyController {
    private final IntegrationService integrationService;
    private final NaturalQueryParser nlpParser;
    private final DatabaseSeeder databaseSeeder;
    private final CsvExportService csvExportService;

    public classifyController(IntegrationService integrationService, NaturalQueryParser nlpParser,
            DatabaseSeeder databaseSeeder, CsvExportService csvExportService) {
        this.integrationService = integrationService;
        this.nlpParser = nlpParser;
        this.databaseSeeder = databaseSeeder;
        this.csvExportService = csvExportService;
    }

    @GetMapping("/")
    public ResponseEntity<String> health() {
        return new ResponseEntity<>("OK", HttpStatus.OK);
    }

    @PostMapping("/api/profiles")
    @RequireRole(Role.ADMIN)
    public ResponseEntity<ProcessedResponse> savePerson(@Valid @RequestBody NewEntityRequest request) {
        String name = request.getName();
        ProcessedResponse response = integrationService.savePerson(name);
        if (response instanceof PersonExistsResponse) {
            return new ResponseEntity<>(response, HttpStatus.OK);
        }
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    @GetMapping("/api/profiles/{id}")
    public ProcessedResponse getUserById(@PathVariable UUID id) {

        Person person = integrationService.getPersonById(id);

        return mapToProcessedResponse(person);
    }

    @GetMapping("/api/profiles")
    public ProfilePageResponse getProfiles(@RequestParam(required = false) String gender,
            @RequestParam(name = "country_id", required = false) String countryId,
            @RequestParam(name = "age_group", required = false) String ageGroup,
            @RequestParam(name = "min_age", required = false) Integer minimumAge,
            @RequestParam(name = "max_age", required = false) Integer maximumAge,
            @RequestParam(name = "min_country_probability", required = false) Double minCountryProbability,
            @RequestParam(name = "min_gender_probability", required = false) Double minGenderProbability,
            @RequestParam(defaultValue = "created_at") String sort_by,
            @RequestParam(defaultValue = "asc") String order,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int limit) {

        if (limit > 50)
            limit = 50;
        if (limit < 1)
            limit = 1;
        if (page < 1)
            page = 1;

        Sort.Direction direction = Sort.Direction.fromString(order);
        String javaField = IntegrationService.mapSortField(sort_by);
        PageRequest pageable = PageRequest.of(page - 1, limit, Sort.by(direction, javaField));

        Page<Person> result = integrationService.searchPeople(
                gender, countryId, ageGroup,
                minimumAge, maximumAge,
                minCountryProbability, minGenderProbability,
                pageable);

        return mapSpecToMultipleProcessedResponse(result, page, limit);
    }

    @DeleteMapping("/api/profiles/{id}")
    @RequireRole(Role.ADMIN)
    public ResponseEntity<String> deleteUserById(@PathVariable UUID id) {
        integrationService.deletePersonById(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/api/profiles/search")
    public ProfilePageResponse searchByNaturalLanguage(
            @RequestParam(required = false) String q,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "10") int limit) {

        if (q == null || q.isBlank()) {
            throw new InvalidQueryParametersException("Invalid query parameters");
        }

        ParsedQuery parsed = nlpParser.parse(q);

        if (parsed == null) {
            throw new UninterpretableQueryException("Unable to interpret query");
        }

        if (limit > 50)
            limit = 50;
        if (page < 1)
            page = 1;

        PageRequest pageable = PageRequest.of(page - 1, limit, Sort.by(Sort.Direction.ASC, "createdAt"));

        Page<Person> result = integrationService.searchPeople(
                parsed.getGender(),
                parsed.getCountryId(),
                parsed.getAgeGroup(),
                parsed.getMinAge(),
                parsed.getMaxAge(),
                null, null,
                pageable);

        return mapSpecToMultipleProcessedResponse(result, page, limit);
    }

    private ProcessedResponse mapToProcessedResponse(Person person) {
        return ProcessedResponse.builder()
                .status("success")
                .data(person)
                .build();
    }

    private ProfilePageResponse mapSpecToMultipleProcessedResponse(Page<Person> page, int pageNum, int limit) {
        int totalPages = page.getTotalPages();

        Map<String, String> links = new java.util.HashMap<>();
        links.put("self", "/api/profiles?page=" + pageNum + "&limit=" + limit);

        if (page.hasNext()) {
            links.put("next", "/api/profiles?page=" + (pageNum + 1) + "&limit=" + limit);
        }

        if (page.hasPrevious()) {
            links.put("prev", "/api/profiles?page=" + (pageNum - 1) + "&limit=" + limit);
        }

        return ProfilePageResponse.builder()
                .status("success")
                .page(pageNum)
                .limit(limit)
                .total(page.getTotalElements())
                .total_pages(totalPages)
                .links(links)
                .data(page.getContent())
                .build();
    }

    @PostMapping("/api/admin/seed")
    @RequireRole(Role.ADMIN)
    public ResponseEntity<String> seedDatabase() {
        try {
            databaseSeeder.seedDatabase();
            return ResponseEntity.ok("Database seeding completed successfully");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Database seeding failed: " + e.getMessage());
        }
    }

    @GetMapping("/api/profiles/export")
    public ResponseEntity<byte[]> exportProfiles(
            @RequestParam(required = false) String gender,
            @RequestParam(name = "country_id", required = false) String countryId,
            @RequestParam(name = "age_group", required = false) String ageGroup,
            @RequestParam(name = "min_age", required = false) Integer minimumAge,
            @RequestParam(name = "max_age", required = false) Integer maximumAge,
            @RequestParam(name = "min_country_probability", required = false) Double minCountryProbability,
            @RequestParam(name = "min_gender_probability", required = false) Double minGenderProbability,
            @RequestParam(defaultValue = "created_at") String sortBy,
            @RequestParam(defaultValue = "asc") String order) {

        byte[] csvData = csvExportService.exportToCsv(gender, countryId, ageGroup, minimumAge, maximumAge,
                minCountryProbability, minGenderProbability, sortBy, order);

        String filename = "profiles_" + System.currentTimeMillis() + ".csv";

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.parseMediaType("text/csv"))
                .body(csvData);
    }

}
