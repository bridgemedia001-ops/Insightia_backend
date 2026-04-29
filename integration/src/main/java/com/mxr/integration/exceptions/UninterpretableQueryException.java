package com.mxr.integration.exceptions;

public class UninterpretableQueryException extends RuntimeException {
    public UninterpretableQueryException(String message) {
        super(message);
    }
}
