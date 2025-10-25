package edu.nu.owaspapivulnlab.web;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.HashMap;
import java.util.Map;

// VULNERABILITY(API7): overly verbose error responses
@ControllerAdvice
public class GlobalErrorHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> all(Exception e) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", e.getClass().getName());
        errorMap.put("message", e.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorMap);
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<?> db(DataAccessException e) {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("dbError", e.getMessage());
        return ResponseEntity.status(500).body(errorMap);
    }
}
