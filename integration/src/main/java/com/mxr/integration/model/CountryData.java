package com.mxr.integration.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class CountryData {
    @JsonProperty("country_id")
    String countryId;
    double probability;
}

