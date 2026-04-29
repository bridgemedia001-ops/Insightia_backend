package com.mxr.integration.Response;

import com.mxr.integration.model.Person;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@Data
@Builder
@AllArgsConstructor
@JsonPropertyOrder({ "status", "data" })
public class ProcessedResponse {
    public String status;
    public Person data;
}
