package edu.nu.owaspapivulnlab.web;

import jakarta.validation.constraints.NotBlank;
// FIX(Task 1): Import Email validation for signup
import jakarta.validation.constraints.Email;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
// FIX(Task 1): Import PasswordEncoder for BCrypt password verification
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import edu.nu.owaspapivulnlab.service.JwtService;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AppUserRepository users;
    private final JwtService jwt;
    // FIX(Task 1): Inject PasswordEncoder for BCrypt password verification during login
    private final PasswordEncoder passwordEncoder;

    public AuthController(AppUserRepository users, JwtService jwt, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.jwt = jwt;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * TASK 9 FIX: Enhanced login request with validation
     * Prevents empty or null credentials
     */
    public static class LoginReq {
        @NotBlank(message = "Username is required")
        private String username;
        
        @NotBlank(message = "Password is required")
        private String password;

        public LoginReq() {}

        public LoginReq(String username, String password) {
            this.username = username;
            this.password = password;
        }

        public String username() { return username; }
        public String password() { return password; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
    }

    public static class TokenRes {
        private String token;

        public TokenRes() {}

        public TokenRes(String token) {
            this.token = token;
        }

        public String getToken() { return token; }
        public void setToken(String token) { this.token = token; }
    }

    /**
     * TASK 9 FIX: Login endpoint with input validation
     * Validates credentials are not blank before processing
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginReq req) {
        // FIX(Task 1): Replace plaintext password comparison with BCrypt verification
        // OLD VULNERABILITY: user.getPassword().equals(req.password()) compared plaintext passwords
        // NEW: passwordEncoder.matches() securely verifies password against BCrypt hash
        AppUser user = users.findByUsername(req.username()).orElse(null);
        if (user != null && passwordEncoder.matches(req.password(), user.getPassword())) {
            Map<String, Object> claims = new HashMap<>();
            claims.put("role", user.getRole());
            claims.put("isAdmin", user.isAdmin()); // VULN: trusts client-side role later
            String token = jwt.issue(user.getUsername(), claims);
            return ResponseEntity.ok(new TokenRes(token));
        }
        Map<String, String> error = new HashMap<>();
        error.put("error", "invalid credentials");
        return ResponseEntity.status(401).body(error);
    }

    // FIX(Task 1): Add signup endpoint to allow user registration with BCrypt password hashing
    // TASK 9 FIX: Enhanced with comprehensive input validation
    // This provides secure user registration with automatic password hashing
    public static class SignupReq {
        @NotBlank(message = "Username is required")
        @jakarta.validation.constraints.Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
        private String username;
        
        @NotBlank(message = "Password is required")
        @jakarta.validation.constraints.Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
        private String password;
        
        @Email(message = "Valid email is required")
        @NotBlank(message = "Email is required")
        private String email;

        public SignupReq() {}

        public SignupReq(String username, String password, String email) {
            this.username = username;
            this.password = password;
            this.email = email;
        }

        public String getUsername() { return username; }
        public String getPassword() { return password; }
        public String getEmail() { return email; }

        public void setUsername(String username) { this.username = username; }
        public void setPassword(String password) { this.password = password; }
        public void setEmail(String email) { this.email = email; }
    }

    /**
     * TASK 9 FIX: Signup endpoint with comprehensive input validation
     * Validates username length, password strength, and email format
     */
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@Valid @RequestBody SignupReq req) {
        // TASK 9 FIX: Additional username validation
        if (req.getUsername().matches(".*[<>\"'].*")) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Username contains invalid characters");
            return ResponseEntity.status(400).body(error);
        }
        
        // Check if username already exists
        if (users.findByUsername(req.getUsername()).isPresent()) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "username already exists");
            return ResponseEntity.status(400).body(error);
        }
        
        // FIX(Task 1): Create new user with BCrypt hashed password
        // Password is automatically hashed using passwordEncoder before saving to database
        AppUser newUser = AppUser.builder()
            .username(req.getUsername())
            .password(passwordEncoder.encode(req.getPassword()))  // Hash password with BCrypt
            .email(req.getEmail())
            .role("USER")  // Default role for new signups
            .isAdmin(false)  // New users are not admins by default
            .build();
        
        users.save(newUser);
        
        Map<String, String> response = new HashMap<>();
        response.put("status", "user created successfully");
        response.put("username", newUser.getUsername());
        return ResponseEntity.status(201).body(response);
    }
}
