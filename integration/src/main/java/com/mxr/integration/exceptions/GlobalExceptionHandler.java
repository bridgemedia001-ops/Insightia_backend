package com.mxr.integration.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.RestClientException;

import com.mxr.integration.Response.ErrorResponse;
import com.mxr.integration.Response.PersonExistsResponse;
import com.mxr.integration.exceptions.AgifyExceptions.NullAgeException;
import com.mxr.integration.exceptions.NationalizeExceptions.MissingCountryDataException;
import com.mxr.integration.repo.PersonRepoImpl;
import com.mxr.integration.exceptions.InvalidQueryParametersException;
import com.mxr.integration.exceptions.UninterpretableQueryException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private final PersonRepoImpl repo;

    public GlobalExceptionHandler(PersonRepoImpl repo) {
        this.repo = repo;
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<ErrorResponse> handleMissingServletRequestParameterException(
            MissingServletRequestParameterException ex) {
        ErrorResponse response = new ErrorResponse(
                "error",
                "Required request parameter is missing");
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);

    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
        ErrorResponse response = new ErrorResponse(
                "error",
                "Invalid request body");
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleHttpMessageNotReadableException(HttpMessageNotReadableException ex) {
        ErrorResponse response = new ErrorResponse("error", "Invalid request body");
        return new ResponseEntity<>(response, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @ExceptionHandler(PersonNotFoundException.class)
    public ResponseEntity<ErrorResponse> handlePersonNotFoundException(PersonNotFoundException ex) {
        ErrorResponse response = new ErrorResponse(
                "error",
                ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(InvalidNameException.class)
    public ResponseEntity<ErrorResponse> handleInvalidNameException(InvalidNameException ex) {
        ErrorResponse response = new ErrorResponse(
                "error",
                ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @ExceptionHandler(MissingOrEmptyNameException.class)
    public ResponseEntity<ErrorResponse> handleMissingOrEmptyNameException(MissingOrEmptyNameException ex) {
        ErrorResponse response = new ErrorResponse(
                "error",
                ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // @ExceptionHandler(PersonAlreadyExistsException.class)
    // public ResponseEntity<PersonExistsResponse>
    // handlePersonAlreadyExistsException(PersonAlreadyExistsException ex){
    // PersonExistsResponse response = new PersonExistsResponse(
    // "error",
    // ex.getMessage(),
    // repo.findByName(ex.getName())
    // );
    // return new ResponseEntity<>(response, HttpStatus.CONFLICT);
    // }

    @ExceptionHandler(MissingGenderizeDataException.class)
    public ResponseEntity<ErrorResponse> handleMissingGenderizeDataException(MissingGenderizeDataException ex) {
        ErrorResponse response = new ErrorResponse(
                "502",
                ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.BAD_GATEWAY);
    }

    @ExceptionHandler(RestClientException.class)
    public ResponseEntity<ErrorResponse> handleRestClientException(RestClientException ex) {
        ErrorResponse response = new ErrorResponse(
                "error",
                ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.BAD_GATEWAY);
    }

    @ExceptionHandler(NullAgeException.class)
    public ResponseEntity<ErrorResponse> handleNullAgeException(NullAgeException ex) {
        ErrorResponse response = new ErrorResponse(
                "502",
                ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.BAD_GATEWAY);
    }

    @ExceptionHandler(MissingCountryDataException.class)
    public ResponseEntity<ErrorResponse> handleMissingCountryDataException(MissingCountryDataException ex) {
        ErrorResponse response = new ErrorResponse(
                "502",
                ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.BAD_GATEWAY);
    }

    @ExceptionHandler(InvalidQueryParametersException.class)
    public ResponseEntity<ErrorResponse> handleInvalidQueryParametersException(InvalidQueryParametersException ex) {
        ErrorResponse response = new ErrorResponse(
                "error",
                ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(UninterpretableQueryException.class)
    public ResponseEntity<ErrorResponse> handleUninterpretableQueryException(UninterpretableQueryException ex) {
        ErrorResponse response = new ErrorResponse(
                "error",
                ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex) {
        ErrorResponse response = new ErrorResponse(
                "error",
                ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleException(Exception ex) {
        ErrorResponse response = new ErrorResponse(
                "error",
                ex.getMessage());
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
