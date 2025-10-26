package edu.nu.owaspapivulnlab.exception;

/**
 * TASK 8 FIX: Custom exception for validation errors
 * Allows specific handling with appropriate HTTP status (400)
 * Provides clear error messages without exposing internal details
 */
public class ValidationException extends RuntimeException {
    public ValidationException(String message) {
        super(message);
    }
}
