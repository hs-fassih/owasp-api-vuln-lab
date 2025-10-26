package edu.nu.owaspapivulnlab.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.Collections;
import java.util.HashMap;
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
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        // FIX(Task 3): Get the account and verify it exists
        Account account = accounts.findById(id)
                .orElseThrow(() -> new RuntimeException("Account not found"));
        
        // FIX(Task 3): Verify ownership - prevent BOLA/IDOR
        // User can only access their own accounts
        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied - you can only view your own accounts");
            return ResponseEntity.status(403).body(error);
        }
        
        // Return balance in a structured response
        Map<String, Object> response = new HashMap<>();
        response.put("accountId", account.getId());
        response.put("balance", account.getBalance());
        return ResponseEntity.ok(response);
    }

    // FIX(Task 3): Added ownership verification and input validation to prevent BOLA/IDOR
    // FIX(Task 9): Added input validation for transfer amount
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount, Authentication auth) {
        // FIX(Task 3): Check if user is authenticated
        if (auth == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Authentication required");
            return ResponseEntity.status(401).body(error);
        }
        
        // FIX(Task 9): Validate transfer amount
        if (amount == null || amount <= 0) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Amount must be positive");
            return ResponseEntity.status(400).body(error);
        }
        
        // FIX(Task 9): Reject excessively large transfers
        if (amount > 1000000) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Amount exceeds maximum transfer limit of 1,000,000");
            return ResponseEntity.status(400).body(error);
        }
        
        // FIX(Task 3): Get the authenticated user
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        // FIX(Task 3): Get the account and verify it exists
        Account account = accounts.findById(id)
                .orElseThrow(() -> new RuntimeException("Account not found"));
        
        // FIX(Task 3): Verify ownership - prevent BOLA/IDOR
        // User can only transfer from their own accounts
        if (!account.getOwnerUserId().equals(currentUser.getId())) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied - you can only transfer from your own accounts");
            return ResponseEntity.status(403).body(error);
        }
        
        // FIX(Task 9): Check sufficient balance
        if (account.getBalance() < amount) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Insufficient balance");
            error.put("available", String.valueOf(account.getBalance()));
            return ResponseEntity.status(400).body(error);
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

    // Safe-ish helper to view my accounts (still leaks more than needed)
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
        return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
    }
}
