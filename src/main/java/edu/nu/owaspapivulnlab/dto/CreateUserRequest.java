package edu.nu.owaspapivulnlab.dto;

import jakarta.validation.constraints.*;
import lombok.*;

/**
 * FIX(Task 6): Create User Request DTO to prevent mass assignment
 * This DTO only accepts safe user input fields
 * Server-side controls role and admin privileges to prevent privilege escalation
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateUserRequest {
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;
    
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;
    
    @Email(message = "Valid email is required")
    @NotBlank(message = "Email is required")
    private String email;
    
    // FIX(Task 6): Dangerous fields intentionally excluded:
    // - role: Server assigns default "USER" role
    // - isAdmin: Server controls admin privileges, not client
    // This prevents privilege escalation attacks via mass assignment
}
