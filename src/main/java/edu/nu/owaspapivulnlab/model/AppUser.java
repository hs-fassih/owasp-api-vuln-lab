package edu.nu.owaspapivulnlab.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.*;

@Entity @Data @NoArgsConstructor @AllArgsConstructor @Builder
public class AppUser {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    private String username;

    // FIX(Task 1): Password field now stores BCrypt hashed passwords instead of plaintext
    // BCrypt hashes are one-way encrypted strings starting with $2a$ or $2b$
    // Original vulnerability: stored plaintext passwords (e.g., "alice123")
    // Fixed: passwords are hashed using BCryptPasswordEncoder before storage
    @NotBlank
    private String password;

    // FIX(Task 6): Mass Assignment Protection
    // These fields (role, isAdmin) are NOT exposed in CreateUserRequest DTO
    // Server-side code explicitly sets these values to prevent privilege escalation
    // VULNERABILITY FIXED: Clients can no longer send {"role":"ADMIN","isAdmin":true} in POST requests
    private String role;   // e.g., "USER" or "ADMIN" - server controlled
    private boolean isAdmin; // Server controlled - cannot be set via API

    @Email
    private String email;
}
