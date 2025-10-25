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

    // VULNERABILITY(API1: BOLA) - no check whether account belongs to caller
    @GetMapping("/{id}/balance")
    public Double balance(@PathVariable Long id) {
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        return a.getBalance();
    }

    // VULNERABILITY(API4: Unrestricted Resource Consumption) - no rate limiting on transfer
    // VULNERABILITY(API5/1): no authorization check on owner
    @PostMapping("/{id}/transfer")
    public ResponseEntity<?> transfer(@PathVariable Long id, @RequestParam Double amount) {
        Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
        a.setBalance(a.getBalance() - amount);
        accounts.save(a);
        Map<String, Object> response = new HashMap<>();
        response.put("status", "ok");
        response.put("remaining", a.getBalance());
        return ResponseEntity.ok(response);
    }

    // Safe-ish helper to view my accounts (still leaks more than needed)
    @GetMapping("/mine")
    public Object mine(Authentication auth) {
        AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
        return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
    }
}
