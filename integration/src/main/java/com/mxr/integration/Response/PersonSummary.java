package com.mxr.integration.Response;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.UUID;
import lombok.Builder;
import lombok.Data;
import lombok.AllArgsConstructor;

@Data
@Builder
@AllArgsConstructor

public class PersonSummary {
    private UUID id;
    private String name;
    private String gender;
    private Integer age;
    @JsonProperty("age_group")
    private String ageGroup;
    @JsonProperty("country_id")
    private String countryId;

}

