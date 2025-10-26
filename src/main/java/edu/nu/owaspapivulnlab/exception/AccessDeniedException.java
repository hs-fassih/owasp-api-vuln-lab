package edu.nu.owaspapivulnlab.exception;

/**
 * TASK 8 FIX: Custom exception for access denied scenarios
 * Allows specific handling with appropriate HTTP status (403)
 * Prevents exposing internal authorization logic to clients
 */
public class AccessDeniedException extends RuntimeException {
    public AccessDeniedException(String message) {
        super(message);
    }
}
