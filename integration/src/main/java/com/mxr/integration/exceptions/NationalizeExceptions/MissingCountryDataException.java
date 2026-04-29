package com.mxr.integration.exceptions.NationalizeExceptions;

public class MissingCountryDataException extends RuntimeException {
    
    public MissingCountryDataException(String message) {
        super(message);
    }
}
