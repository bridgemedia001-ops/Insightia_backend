package com.mxr.integration.exceptions;

public class InvalidQueryParametersException extends RuntimeException {
    public InvalidQueryParametersException(String message) {
        super(message);
    }
}
