package com.mxr.integration.Response;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.mxr.integration.model.CountryData;

import java.util.List;

import lombok.Data;

@Data
public class NationalizeResponse {
    int count;
    String name;
    @JsonProperty("country")
    List<CountryData> countries;
}