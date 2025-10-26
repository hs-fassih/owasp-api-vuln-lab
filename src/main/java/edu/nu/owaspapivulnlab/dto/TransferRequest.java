package edu.nu.owaspapivulnlab.dto;

import jakarta.validation.constraints.*;
import lombok.*;

/**
 * TASK 9 FIX: Transfer Request DTO with input validation
 * Prevents injection of negative or excessively large transfer amounts
 * Addresses API9:2023 - Improper Assets Management / Input Validation
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TransferRequest {
    
    /**
     * TASK 9 FIX: Validate transfer amount is positive and within acceptable limits
     * - @NotNull: Prevents null amounts
     * - @DecimalMin: Rejects negative amounts and zero
     * - @DecimalMax: Prevents unrealistically large transfers that could cause overflow
     * - @Digits: Limits precision to prevent floating point issues
     */
    @NotNull(message = "Amount is required")
    @DecimalMin(value = "0.01", inclusive = true, message = "Amount must be at least 0.01")
    @DecimalMax(value = "1000000.00", inclusive = true, message = "Amount cannot exceed 1,000,000")
    @Digits(integer = 7, fraction = 2, message = "Amount must be a valid monetary value (max 7 digits, 2 decimals)")
    private Double amount;
    
    /**
     * TASK 9 FIX: Optional validation for destination account
     * Can be extended for full peer-to-peer transfers in the future
     */
    @Min(value = 1, message = "Destination account ID must be positive")
    private Long destinationAccountId;
}
