package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
// FIX(Task 4): Import DTOs for safe data exposure
import edu.nu.owaspapivulnlab.dto.AccountResponseDTO;
import edu.nu.owaspapivulnlab.dto.DTOMapper;
// TASK 9 FIX: Import TransferRequest DTO for input validation
import edu.nu.owaspapivulnlab.dto.TransferRequest;
// TASK 8 FIX: Import custom exceptions for proper error handling
import edu.nu.owaspapivulnlab.exception.AccessDeniedException;
import edu.nu.owaspapivulnlab.exception.ResourceNotFoundException;
import edu.nu.owaspapivulnlab.exception.ValidationException;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accounts;
    private final AppUserRepository users;

    public AccountController(AccountRepository accounts, AppUserRepository users) {
        this.accounts = accounts;
        this.users = users;
    }

    // FIX(Task 3): Added ownership verification to prevent BOLA/IDOR attacks
    // Users can only view balances of their own accounts
    @GetMapping("/{id}/balance")
    public ResponseEntity<?> balance(@PathVariable Long id, Authentication auth) {
        // FIX(Task 3): Check if user is authenticated
        if (auth == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Authentication required");
            return ResponseEntity.status(401).body(error);
        }
        
        // FIX(Task 3): Get the authenticated user
        // TASK 8 FIX: Use ResourceNotFoundException for consistent error handling
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        
        // FIX(Task 3): Get the account and verify it exists
        // TASK 8 FIX: Use ResourceNotFoundException for consistent error handling
        Account account = accounts.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Account not found"));
        
        // FIX(Task 3): Verify ownership - prevent BOLA/IDOR
        // User can only access their own accounts
        // TASK 8 FIX: Use AccessDeniedException for consistent error handling
        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            throw new AccessDeniedException("Access denied - you can only view your own accounts");
        }
        
        // Return balance in a structured response
        Map<String, Object> response = new HashMap<>();
        response.put("accountId", account.getId());
        response.put("balance", account.getBalance());
        return ResponseEntity.ok(response);
    }

    // FIX(Task 3): Added ownership verification and input validation to prevent BOLA/IDOR
    // TASK 9 FIX: Enhanced input validation using TransferRequest DTO with Jakarta validation
    // Validates: positive amounts, maximum limits, proper decimal precision
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(
            @PathVariable Long id, 
            @Valid @RequestBody TransferRequest transferRequest,
            Authentication auth) {
        
        // FIX(Task 3): Check if user is authenticated
        if (auth == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Authentication required");
            return ResponseEntity.status(401).body(error);
        }
        
        // TASK 9 FIX: Extract validated amount from DTO
        // Jakarta Bean Validation already ensures:
        // - Amount is not null
        // - Amount >= 0.01 (prevents negative and zero)
        // - Amount <= 1,000,000 (prevents excessive transfers)
        // - Proper decimal format (7 integer digits, 2 fractional)
        Double amount = transferRequest.getAmount();
        
        // FIX(Task 3): Get the authenticated user
        // TASK 8 FIX: Use ResourceNotFoundException for consistent error handling
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        
        // FIX(Task 3): Get the account and verify it exists
        // TASK 8 FIX: Use ResourceNotFoundException for consistent error handling
        Account account = accounts.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Account not found"));
        
        // FIX(Task 3): Verify ownership - prevent BOLA/IDOR
        // User can only transfer from their own accounts
        // TASK 8 FIX: Use AccessDeniedException for consistent error handling
        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            throw new AccessDeniedException("Access denied - you can only transfer from your own accounts");
        }
        
        // TASK 9 FIX: Check sufficient balance before transfer
        // TASK 8 FIX: Use ValidationException for consistent error handling
        if (account.getBalance() < amount) {
            throw new ValidationException("Insufficient balance. Available: " + account.getBalance());
        }
        
        // TASK 9 FIX: Additional business rule validation
        // Prevent suspicious small transfers that could indicate testing/enumeration
        if (amount < 0.01) {
            throw new ValidationException("Minimum transfer amount is 0.01");
        }
        
        // Perform transfer
        account.setBalance(account.getBalance() - amount);
        accounts.save(account);
        
        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", account.getBalance());
        response.put("transferred", amount);
        return ResponseEntity.ok(response);
    }

    // FIX(Task 4): Updated to return DTOs instead of raw entities
    // Prevents exposing internal fields like ownerUserId
    @GetMapping("/mine")
    public ResponseEntity<?> mine(Authentication auth) {
        // Check authentication
        if (auth == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Authentication required");
            return ResponseEntity.status(401).body(error);
        }
        
        // Get authenticated user
        AppUser me = users.findByUsername(auth.getName()).orElse(null);
        if (me == null) {
            return ResponseEntity.ok(Collections.emptyList());
        }
        
        // FIX(Task 4): Convert entities to DTOs before returning
        // This prevents exposing ownerUserId field to clients
        List<Account> userAccounts = accounts.findByOwnerUserId(me.getId());
        List<AccountResponseDTO> accountDTOs = DTOMapper.toAccountDTOList(userAccounts);
        
        return ResponseEntity.ok(accountDTOs);
    }
}
