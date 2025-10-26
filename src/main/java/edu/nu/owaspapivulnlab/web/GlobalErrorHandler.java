package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.dto.ErrorResponse;
import edu.nu.owaspapivulnlab.exception.AccessDeniedException;
import edu.nu.owaspapivulnlab.exception.ResourceNotFoundException;
import edu.nu.owaspapivulnlab.exception.ValidationException;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.LocalDateTime;
import java.util.stream.Collectors;

/**
 * TASK 8 FIX: Improved Global Exception Handler
 * 
 * OWASP API7:2023 - Security Misconfiguration
 * 
 * Original Vulnerability:
 * - Exposed full exception class names and internal messages to clients
 * - Leaked database schema details through SQL exceptions
 * - Included stack traces in responses (server.error.include-stacktrace=always)
 * - No logging of security-relevant errors
 * - Generic error handling revealed system internals
 * 
 * Security Improvements:
 * 1. Environment-aware error responses (detailed in dev, minimal in prod)
 * 2. Specific exception handlers for different error types
 * 3. Sanitized error messages that don't expose internals
 * 4. Proper HTTP status codes for different scenarios
 * 5. Security event logging for auditing
 * 6. No stack traces in production responses
 */
@ControllerAdvice
public class GlobalErrorHandler {
    
    private static final Logger log = LoggerFactory.getLogger(GlobalErrorHandler.class);
    
    // TASK 8 FIX: Environment-based error detail control
    // In production, set spring.profiles.active=prod to minimize error exposure
    @Value("${spring.profiles.active:dev}")
    private String activeProfile;
    
    /**
     * TASK 8 FIX: Handle resource not found exceptions (404)
     * Examples: User not found, Account not found
     */
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleResourceNotFound(
            ResourceNotFoundException ex, 
            HttpServletRequest request) {
        
        log.warn("Resource not found: {} at {}", ex.getMessage(), request.getRequestURI());
        
        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.NOT_FOUND.value())
                .error("Not Found")
                .message(ex.getMessage())
                .path(request.getRequestURI())
                .build();
        
        // Only include debug info in development
        if (isDevelopment()) {
            error.setDebugMessage(ex.getMessage());
            error.setExceptionType(ex.getClass().getSimpleName());
        }
        
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }
    
    /**
     * TASK 8 FIX: Handle access denied exceptions (403)
     * Examples: Non-admin trying to access admin endpoint, accessing someone else's resource
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
            AccessDeniedException ex, 
            HttpServletRequest request) {
        
        // TASK 8 FIX: Log security events for audit trail
        log.warn("Access denied: {} at {} from IP {}", 
                ex.getMessage(), 
                request.getRequestURI(),
                getClientIp(request));
        
        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.FORBIDDEN.value())
                .error("Access Denied")
                // TASK 8 FIX: Generic message in production, specific in dev
                .message(isDevelopment() ? ex.getMessage() : "You don't have permission to access this resource")
                .path(request.getRequestURI())
                .build();
        
        if (isDevelopment()) {
            error.setDebugMessage(ex.getMessage());
            error.setExceptionType(ex.getClass().getSimpleName());
        }
        
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error);
    }
    
    /**
     * TASK 8 FIX: Handle authentication exceptions (401)
     * Examples: Invalid JWT, expired token, missing credentials
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleAuthenticationException(
            AuthenticationException ex, 
            HttpServletRequest request) {
        
        // TASK 8 FIX: Log failed authentication attempts for security monitoring
        log.warn("Authentication failed: {} at {} from IP {}", 
                ex.getMessage(), 
                request.getRequestURI(),
                getClientIp(request));
        
        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.UNAUTHORIZED.value())
                .error("Unauthorized")
                // TASK 8 FIX: Don't reveal why authentication failed in production
                .message(isDevelopment() ? ex.getMessage() : "Authentication required")
                .path(request.getRequestURI())
                .build();
        
        if (isDevelopment()) {
            error.setDebugMessage(ex.getMessage());
            error.setExceptionType(ex.getClass().getSimpleName());
        }
        
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
    }
    
    /**
     * TASK 8 FIX: Handle validation exceptions (400)
     * Examples: Invalid email format, password too short, negative transfer amount
     */
    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(
            ValidationException ex, 
            HttpServletRequest request) {
        
        log.debug("Validation error: {} at {}", ex.getMessage(), request.getRequestURI());
        
        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Validation Error")
                .message(ex.getMessage())
                .path(request.getRequestURI())
                .build();
        
        if (isDevelopment()) {
            error.setDebugMessage(ex.getMessage());
            error.setExceptionType(ex.getClass().getSimpleName());
        }
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }
    
    /**
     * TASK 8 FIX: Handle Bean Validation errors (400)
     * Examples: @NotBlank, @Email, @Size constraint violations
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpServletRequest request) {
        
        // Collect all validation error messages
        String validationErrors = ex.getBindingResult().getFieldErrors().stream()
                .map(FieldError::getDefaultMessage)
                .collect(Collectors.joining("; "));
        
        log.debug("Validation failed: {} at {}", validationErrors, request.getRequestURI());
        
        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.BAD_REQUEST.value())
                .error("Validation Error")
                .message("Invalid input: " + validationErrors)
                .path(request.getRequestURI())
                .build();
        
        if (isDevelopment()) {
            error.setDebugMessage(validationErrors);
            error.setExceptionType(ex.getClass().getSimpleName());
        }
        
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }
    
    /**
     * TASK 8 FIX: Handle database exceptions (500)
     * CRITICAL: Never expose SQL queries or database schema in production!
     */
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ErrorResponse> handleDataAccessException(
            DataAccessException ex,
            HttpServletRequest request) {
        
        // TASK 8 FIX: Log full error for ops team, sanitize for client
        log.error("Database error at {}: {}", request.getRequestURI(), ex.getMessage(), ex);
        
        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .error("Internal Server Error")
                // TASK 8 FIX: Generic message in production, never expose SQL details
                .message(isDevelopment() 
                        ? "Database error: " + ex.getMostSpecificCause().getMessage()
                        : "An error occurred while processing your request")
                .path(request.getRequestURI())
                .build();
        
        // TASK 8 FIX: Only include database details in development for debugging
        if (isDevelopment()) {
            error.setDebugMessage(ex.getMostSpecificCause().getMessage());
            error.setExceptionType(ex.getClass().getSimpleName());
        }
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
    
    /**
     * TASK 8 FIX: Handle all other unexpected exceptions (500)
     * Catches any exception not handled by specific handlers above
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneralException(
            Exception ex,
            HttpServletRequest request) {
        
        // TASK 8 FIX: Log full stack trace for ops team investigation
        log.error("Unexpected error at {}: {}", request.getRequestURI(), ex.getMessage(), ex);
        
        ErrorResponse error = ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                .error("Internal Server Error")
                // TASK 8 FIX: Never expose internal exception details in production
                .message(isDevelopment() 
                        ? "Error: " + ex.getMessage()
                        : "An unexpected error occurred. Please try again later.")
                .path(request.getRequestURI())
                .build();
        
        // TASK 8 FIX: Only include exception details in development
        if (isDevelopment()) {
            error.setDebugMessage(ex.getMessage());
            error.setExceptionType(ex.getClass().getName());
        }
        
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
    
    /**
     * TASK 8 FIX: Check if running in development mode
     */
    private boolean isDevelopment() {
        return "dev".equalsIgnoreCase(activeProfile) || "development".equalsIgnoreCase(activeProfile);
    }
    
    /**
     * TASK 8 FIX: Extract client IP for security logging
     * Handles proxy scenarios (X-Forwarded-For header)
     */
    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
