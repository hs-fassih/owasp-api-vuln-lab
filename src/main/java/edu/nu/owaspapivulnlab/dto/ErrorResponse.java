package edu.nu.owaspapivulnlab.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * TASK 8 FIX: Standard error response DTO
 * Provides consistent error format across all endpoints
 * Controls what information is exposed to clients
 * Prevents leaking internal details like stack traces in production
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {
    
    // Timestamp when error occurred
    private LocalDateTime timestamp;
    
    // HTTP status code (e.g., 400, 403, 404, 500)
    private int status;
    
    // Short error type (e.g., "Validation Error", "Not Found")
    private String error;
    
    // User-friendly error message (safe to expose)
    private String message;
    
    // API path where error occurred
    private String path;
    
    // TASK 8 FIX: Development-only fields (excluded in production)
    // These help developers debug but shouldn't be exposed to end users
    private String debugMessage;  // Only in dev: detailed error info
    private String exceptionType; // Only in dev: exception class name
}
