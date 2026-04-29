package com.mxr.integration.exceptions;

public class MissingOrEmptyNameException extends RuntimeException {
    private String name;

    public MissingOrEmptyNameException(String message, String name) {
        super(message);
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
