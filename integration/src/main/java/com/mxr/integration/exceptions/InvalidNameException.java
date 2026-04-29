package com.mxr.integration.exceptions;

public class InvalidNameException extends RuntimeException{
    public InvalidNameException(String message){
        super(message);
    }    
}
