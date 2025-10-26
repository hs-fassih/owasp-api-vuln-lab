package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
// FIX(Task 3): Import Authentication for ownership verification
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;

    public UserController(AppUserRepository users) {
        this.users = users;
    }

    // FIX(Task 3): Added ownership verification to prevent BOLA/IDOR attacks
    // Users can only view their own profile, admins can view any profile
    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable Long id, Authentication auth) {
        // FIX(Task 3): Check if user is authenticated
        if (auth == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Authentication required");
            return ResponseEntity.status(401).body(error);
        }
        
        // FIX(Task 3): Get the authenticated user
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        // FIX(Task 3): Verify ownership or admin privilege
        // Users can only view their own profile, unless they are admins
        if (!currentUser.getId().equals(id) && !currentUser.isAdmin()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied - you can only view your own profile");
            return ResponseEntity.status(403).body(error);
        }
        
        // Get the requested user
        AppUser user = users.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        // TODO(Task 4): Return DTO instead of full entity to avoid exposing sensitive data
        return ResponseEntity.ok(user);
    }

    // VULNERABILITY(API6: Mass Assignment) - binds role/isAdmin from client
    @PostMapping
    public AppUser create(@Valid @RequestBody AppUser body) {
        return users.save(body);
    }

    // VULNERABILITY(API9: Improper Inventory + API8 Injection style): naive 'search' that can be abused for enumeration
    @GetMapping("/search")
    public List<AppUser> search(@RequestParam String q) {
        return users.search(q);
    }

    // VULNERABILITY(API3: Excessive Data Exposure) - returns all users including sensitive fields
    @GetMapping
    public List<AppUser> list() {
        return users.findAll();
    }

    // FIX(Task 3): Added authorization check to prevent unauthorized deletions
    // Only admins can delete users, and they cannot delete themselves
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id, Authentication auth) {
        // FIX(Task 3): Check if user is authenticated
        if (auth == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Authentication required");
            return ResponseEntity.status(401).body(error);
        }
        
        // FIX(Task 3): Get the authenticated user
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));
        
        // FIX(Task 3): Only admins can delete users (prevent privilege escalation)
        if (!currentUser.isAdmin()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Access denied - admin privileges required");
            return ResponseEntity.status(403).body(error);
        }
        
        // FIX(Task 3): Prevent admins from deleting themselves
        if (currentUser.getId().equals(id)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "You cannot delete your own account");
            return ResponseEntity.status(400).body(error);
        }
        
        // Verify user exists before deletion
        if (!users.existsById(id)) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "User not found");
            return ResponseEntity.status(404).body(error);
        }
        
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        response.put("message", "User successfully deleted");
        return ResponseEntity.ok(response);
    }
}
