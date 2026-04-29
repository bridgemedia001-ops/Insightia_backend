package com.mxr.integration.Response;

import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class AgifyResponse {
    int count;
    String name;
    @NotNull
    Integer age;
    
}
