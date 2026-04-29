package com.mxr.integration.exceptions;

public class PersonAlreadyExistsException extends RuntimeException {

    private String name;
    public PersonAlreadyExistsException(String name) {
        super(String.format("Person %s already exists", name));
        this.name = name;
    }

    public String getName() {
        return name;
    }

}
