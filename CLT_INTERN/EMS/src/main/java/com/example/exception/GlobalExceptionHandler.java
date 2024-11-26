package com.example.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
	 @ExceptionHandler(ResourceNotFoundException.class)
	    public ResponseEntity<?> handlerResourceNotFoundException(ResourceNotFoundException ex){
	         String message = ex.getMessage();
	         return new ResponseEntity<>(message,HttpStatus.NOT_FOUND);
	    }
	 @ExceptionHandler(EmployeeNotFoundException.class)
	    public ResponseEntity<String> handleUserNotFoundException(EmployeeNotFoundException ex) {
		 String message = ex.getMessage();
         return new ResponseEntity<>(message,HttpStatus.NOT_FOUND);
	 }
}
