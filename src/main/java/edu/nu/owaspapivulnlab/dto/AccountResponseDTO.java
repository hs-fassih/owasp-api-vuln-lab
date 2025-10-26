package edu.nu.owaspapivulnlab.dto;

import lombok.*;

/**
 * FIX(Task 4): Account Response DTO to control data exposure
 * This DTO prevents exposing internal implementation details
 * Only information relevant to the account holder is included
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccountResponseDTO {
    private Long id;
    private String iban;
    private Double balance;
    
    // FIX(Task 4): Sensitive fields intentionally excluded:
    // - ownerUserId: Internal foreign key, not relevant for API responses
    //   The client already knows they own this account from the authentication context
}
