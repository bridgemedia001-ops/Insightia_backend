package com.mxr.integration.exceptions;

public class MissingApiVersionHeaderException extends RuntimeException {
    public MissingApiVersionHeaderException(String message) {
        super(message);
    }
}
