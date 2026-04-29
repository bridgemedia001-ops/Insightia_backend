package com.mxr.integration.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class NewEntityRequest {
    @Valid
    @NotBlank
    private String name;
}
