package edu.nu.owaspapivulnlab.dto;

import lombok.*;

/**
 * FIX(Task 4): User Response DTO to control data exposure
 * This DTO prevents exposing sensitive fields like password, role, and isAdmin flag
 * Only safe, non-sensitive user information is included in API responses
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponseDTO {
    private Long id;
    private String username;
    private String email;
    
    // FIX(Task 4): Sensitive fields intentionally excluded:
    // - password: Never expose password hashes
    // - role: Internal authorization detail, not for client consumption
    // - isAdmin: Internal flag, should not be exposed to clients
}
