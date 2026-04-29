package com.mxr.integration.Response;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor

public class ErrorResponse {
    public String status;
    public String message;
}
