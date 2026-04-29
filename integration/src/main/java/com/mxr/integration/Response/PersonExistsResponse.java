package com.mxr.integration.Response;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.mxr.integration.model.Person;
import lombok.Data;

@Data
@JsonPropertyOrder({ "status", "message", "data" })

public class PersonExistsResponse extends ProcessedResponse {
    public String message;

    public PersonExistsResponse(String status, Person data, String message) {
        super(status, data);
        this.message = message;
    }
}
