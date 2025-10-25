package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
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

    // VULNERABILITY(API1: BOLA/IDOR) - no ownership check, any authenticated OR anonymous GET (due to SecurityConfig) can fetch any user
    @GetMapping("/{id}")
    public AppUser get(@PathVariable Long id) {
        return users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
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

    // VULNERABILITY(API5: Broken Function Level Authorization) - allows regular users to delete anyone
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
}
