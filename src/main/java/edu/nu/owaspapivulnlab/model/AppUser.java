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

    // FIXED VULNERABILITY IN USER CONTROLLER:using DTO and setting role/isAdmin manually VULNERABILITY(API6: Mass Assignment): role and isAdmin are bindable via incoming JSON
    private String role;   // e.g., "USER" or "ADMIN"
    private boolean isAdmin;

    @Email
    private String email;
}
