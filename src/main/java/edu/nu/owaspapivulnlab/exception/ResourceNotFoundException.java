package edu.nu.owaspapivulnlab.exception;

/**
 * TASK 8 FIX: Custom exception for resource not found scenarios
 * Allows specific handling with appropriate HTTP status (404)
 * Prevents exposing internal exception details to clients
 */
public class ResourceNotFoundException extends RuntimeException {
    public ResourceNotFoundException(String message) {
        super(message);
    }
}
