package edu.nu.owaspapivulnlab.web;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
// FIX(Task 3): Import Authentication for ownership verification
import org.springframework.security.core.Authentication;
// FIX(Task 4): Import PasswordEncoder for secure password handling
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
// FIX(Task 4): Import DTOs for safe data exposure
import edu.nu.owaspapivulnlab.dto.UserResponseDTO;
import edu.nu.owaspapivulnlab.dto.CreateUserRequest;
import edu.nu.owaspapivulnlab.dto.DTOMapper;
// TASK 8 FIX: Import custom exceptions for proper error handling
import edu.nu.owaspapivulnlab.exception.AccessDeniedException;
import edu.nu.owaspapivulnlab.exception.ResourceNotFoundException;
import edu.nu.owaspapivulnlab.exception.ValidationException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    // FIX(Task 4/6): Inject PasswordEncoder for secure user creation
    private final PasswordEncoder passwordEncoder;

    public UserController(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder;
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
        // TASK 8 FIX: Use ResourceNotFoundException for consistent error handling
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        
        // FIX(Task 3): Verify ownership or admin privilege
        // Users can only view their own profile, unless they are admins
        // TASK 8 FIX: Use AccessDeniedException for consistent error handling
        if (!currentUser.getId().equals(id) && !currentUser.isAdmin()) {
            throw new AccessDeniedException("Access denied - you can only view your own profile");
        }
        
        // Get the requested user
        // TASK 8 FIX: Use ResourceNotFoundException for consistent error handling
        AppUser user = users.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        
        // FIX(Task 4): Return DTO instead of full entity to avoid exposing sensitive data
        // Prevents exposing password hash, role, and isAdmin flag
        UserResponseDTO userDTO = DTOMapper.toUserDTO(user);
        return ResponseEntity.ok(userDTO);
    }

    // FIX(Task 6): Prevent mass assignment by using explicit DTO without role/isAdmin
    // Uses CreateUserRequest DTO which only accepts username, password, and email
    // Server controls role and isAdmin assignments to prevent privilege escalation
    @PostMapping
    public ResponseEntity<?> create(@Valid @RequestBody CreateUserRequest body, Authentication auth) {
        // FIX(Task 3): Require authentication for user creation
        if (auth == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Authentication required");
            return ResponseEntity.status(401).body(error);
        }
        
        // FIX(Task 3): Only admins can create users
        // TASK 8 FIX: Use ResourceNotFoundException for consistent error handling
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        
        // TASK 8 FIX: Use AccessDeniedException for consistent error handling
        if (!currentUser.isAdmin()) {
            throw new AccessDeniedException("Access denied - admin privileges required");
        }
        
        // Check if username already exists
        // TASK 8 FIX: Use ValidationException for consistent error handling
        if (users.findByUsername(body.getUsername()).isPresent()) {
            throw new ValidationException("Username already exists");
        }
        
        // FIX(Task 6): Create user with safe defaults - server controls role/isAdmin
        // FIX(Task 4): Hash password before storage (never store plaintext!)
        AppUser user = AppUser.builder()
            .username(body.getUsername())
            .password(passwordEncoder.encode(body.getPassword()))  // Hash password with BCrypt
            .email(body.getEmail())
            .role("USER")               // Server controls: default to USER role
            .isAdmin(false)             // Server controls: prevent privilege escalation
            .build();
        
        AppUser savedUser = users.save(user);
        
        // FIX(Task 4): Return DTO to avoid exposing password hash, role, isAdmin
        UserResponseDTO userDTO = DTOMapper.toUserDTO(savedUser);
        return ResponseEntity.ok(userDTO);
    }

    // FIX(Task 4): Return DTOs to prevent exposing sensitive user data in search results
    // TASK 9 FIX: Enhanced with input validation to prevent injection attacks
    // REMAINING VULNERABILITY(API9): Search still allows enumeration (mitigated by rate limiting in Task 5)
    @GetMapping("/search")
    public ResponseEntity<?> search(@RequestParam String q, Authentication auth) {
        // Require authentication for search
        if (auth == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Authentication required");
            return ResponseEntity.status(401).body(error);
        }
        
        // TASK 9 FIX: Validate search query input
        if (q == null || q.trim().isEmpty()) {
            throw new ValidationException("Search query cannot be empty");
        }
        
        // TASK 9 FIX: Prevent excessively long search queries (potential DoS)
        if (q.length() > 100) {
            throw new ValidationException("Search query too long (max 100 characters)");
        }
        
        // TASK 9 FIX: Sanitize search input to prevent SQL injection patterns
        // Note: Since we're using Spring Data JPA with parameterized queries, this is defense-in-depth
        if (q.matches(".*[;'\"\\\\].*")) {
            throw new ValidationException("Search query contains invalid characters");
        }
        
        // Perform search and convert to DTOs
        List<AppUser> searchResults = users.search(q);
        
        // FIX(Task 4): Convert to DTOs to prevent exposing passwords, roles, and admin flags
        List<UserResponseDTO> resultDTOs = DTOMapper.toUserDTOList(searchResults);
        
        return ResponseEntity.ok(resultDTOs);
    }

    // FIX(Task 4): Return DTOs to prevent exposing sensitive user data
    // FIX(Task 3): Require authentication to list users
    @GetMapping
    public ResponseEntity<?> list(Authentication auth) {
        // Require authentication
        if (auth == null) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Authentication required");
            return ResponseEntity.status(401).body(error);
        }
        
        // Get all users and convert to DTOs
        List<AppUser> allUsers = users.findAll();
        
        // FIX(Task 4): Convert to DTOs to prevent exposing passwords, roles, and admin flags
        List<UserResponseDTO> userDTOs = DTOMapper.toUserDTOList(allUsers);
        
        return ResponseEntity.ok(userDTOs);
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
        // TASK 8 FIX: Use ResourceNotFoundException for consistent error handling
        AppUser currentUser = users.findByUsername(auth.getName())
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));
        
        // FIX(Task 3): Only admins can delete users (prevent privilege escalation)
        // TASK 8 FIX: Use AccessDeniedException for consistent error handling
        if (!currentUser.isAdmin()) {
            throw new AccessDeniedException("Access denied - admin privileges required");
        }
        
        // FIX(Task 3): Prevent admins from deleting themselves
        // TASK 8 FIX: Use ValidationException for consistent error handling
        if (currentUser.getId().equals(id)) {
            throw new ValidationException("You cannot delete your own account");
        }
        
        // Verify user exists before deletion
        // TASK 8 FIX: Use ResourceNotFoundException for consistent error handling
        if (!users.existsById(id)) {
            throw new ResourceNotFoundException("User not found");
        }
        
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        response.put("message", "User successfully deleted");
        return ResponseEntity.ok(response);
    }
}