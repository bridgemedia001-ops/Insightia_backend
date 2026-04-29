package com.mxr.integration.model;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@Data
@Builder
@JsonPropertyOrder({"name", "gender", "probability", "sample_size", "is_confident", "processed_at"})
public class GenderData {
    public String name;
    public String gender;
    public double probability;
    @JsonProperty("sample_size")
    public int sampleSize;
    public boolean confident;
    @JsonProperty("processed_at")
    public String processedAt;
}
