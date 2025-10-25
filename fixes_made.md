# Security Fixes Documentation

## Task 1: Replace Plaintext Passwords with BCrypt

### Overview
Fixed the critical security vulnerability where passwords were stored in plaintext in the database. Implemented BCrypt password hashing to securely store and verify user credentials.

### Vulnerability Description
**OWASP API Security Category:** API2 - Broken Authentication & API3 - Excessive Data Exposure

**Original Issue:**
- Passwords were stored as plaintext strings in the database (e.g., "alice123", "bob123")
- Login authentication used simple string comparison: `user.getPassword().equals(req.password())`
- Anyone with database access could read all user passwords
- No secure password hashing mechanism was in place

### Changes Made

#### 1. SecurityConfig.java
**Location:** `src/main/java/edu/nu/owaspapivulnlab/config/SecurityConfig.java`

**Changes:**
- Added import for `BCryptPasswordEncoder` and `PasswordEncoder`
- Created a `@Bean` method `passwordEncoder()` that returns a `BCryptPasswordEncoder` instance
- This bean is now available for dependency injection throughout the application

**Code Added:**
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

**Impact:** Provides a centralized password encoder that can be injected into any component that needs to hash or verify passwords.

---

#### 2. DataSeeder.java
**Location:** `src/main/java/edu/nu/owaspapivulnlab/config/DataSeeder.java`

**Changes:**
- Added import for `PasswordEncoder`
- Modified the `seed()` method signature to inject `PasswordEncoder encoder`
- Updated seed data creation to hash passwords using `encoder.encode()` before saving users

**Before:**
```java
AppUser u1 = users.save(AppUser.builder()
    .username("alice")
    .password("alice123")  // Plaintext password
    ...
```

**After:**
```java
AppUser u1 = users.save(AppUser.builder()
    .username("alice")
    .password(encoder.encode("alice123"))  // BCrypt hashed password
    ...
```

**Impact:** 
- Seed users (alice and bob) now have BCrypt hashed passwords in the database
- Passwords in database look like: `$2a$10$xYz...` instead of plaintext
- Existing users will need database reset or migration to work with new hashing

---

#### 3. AuthController.java
**Location:** `src/main/java/edu/nu/owaspapivulnlab/web/AuthController.java`

**Changes:**

##### a) Added PasswordEncoder Dependency
- Added `PasswordEncoder` field to the controller
- Updated constructor to inject `PasswordEncoder`
- Added necessary imports for validation annotations

**Code:**
```java
private final PasswordEncoder passwordEncoder;

public AuthController(AppUserRepository users, JwtService jwt, PasswordEncoder passwordEncoder) {
    this.users = users;
    this.jwt = jwt;
    this.passwordEncoder = passwordEncoder;
}
```

##### b) Updated Login Method
- Replaced plaintext password comparison with BCrypt verification
- Changed from: `user.getPassword().equals(req.password())`
- Changed to: `passwordEncoder.matches(req.password(), user.getPassword())`

**Before:**
```java
if (user != null && user.getPassword().equals(req.password())) {
    // Login successful
}
```

**After:**
```java
if (user != null && passwordEncoder.matches(req.password(), user.getPassword())) {
    // Login successful - BCrypt verification
}
```

**Impact:**
- Login now securely verifies passwords against BCrypt hashes
- `passwordEncoder.matches()` compares the plaintext input with the stored hash
- Timing-attack resistant comparison built into BCrypt

##### c) Added Signup Endpoint
- Created new `SignupReq` DTO class with validation annotations
- Implemented `POST /api/auth/signup` endpoint
- Automatically hashes passwords during user registration
- Validates username uniqueness
- Sets default role as "USER" and isAdmin as false

**New Endpoint:**
```java
@PostMapping("/signup")
public ResponseEntity<?> signup(@Valid @RequestBody SignupReq req) {
    // Check for duplicate username
    if (users.findByUsername(req.getUsername()).isPresent()) {
        return ResponseEntity.status(400).body(error);
    }
    
    // Create user with hashed password
    AppUser newUser = AppUser.builder()
        .username(req.getUsername())
        .password(passwordEncoder.encode(req.getPassword()))  // Hash password
        .email(req.getEmail())
        .role("USER")
        .isAdmin(false)
        .build();
    
    users.save(newUser);
    return ResponseEntity.status(201).body(response);
}
```

**Request Format:**
```json
{
    "username": "newuser",
    "password": "securepassword123",
    "email": "user@example.com"
}
```

**Response (Success):**
```json
{
    "status": "user created successfully",
    "username": "newuser"
}
```

**Response (Error - Duplicate Username):**
```json
{
    "error": "username already exists"
}
```

**Impact:**
- Users can now register securely through the API
- All new passwords are automatically BCrypt hashed
- Server-side validation ensures data integrity
- Prevents privilege escalation by enforcing default USER role

---

#### 4. AppUser.java (Model)
**Location:** `src/main/java/edu/nu/owaspapivulnlab/model/AppUser.java`

**Changes:**
- Updated comment on the `password` field to reflect the fix
- Documented that the field now stores BCrypt hashes instead of plaintext

**Updated Comment:**
```java
// FIX(Task 1): Password field now stores BCrypt hashed passwords instead of plaintext
// BCrypt hashes are one-way encrypted strings starting with $2a$ or $2b$
// Original vulnerability: stored plaintext passwords (e.g., "alice123")
// Fixed: passwords are hashed using BCryptPasswordEncoder before storage
@NotBlank
private String password;
```

**Impact:** 
- Improved code documentation
- Helps future developers understand the security implementation
- No functional change to the model itself

---

### Security Benefits

1. **Password Confidentiality:**
   - Passwords are never stored in plaintext
   - Database compromise doesn't reveal actual user passwords
   - BCrypt hashes are computationally expensive to reverse

2. **Industry Standard:**
   - BCrypt is a well-tested, industry-standard password hashing algorithm
   - Includes built-in salt to prevent rainbow table attacks
   - Adaptive cost factor can be increased as computing power grows

3. **Secure Verification:**
   - `passwordEncoder.matches()` performs constant-time comparison
   - Resistant to timing attacks
   - Automatic salt handling during verification

4. **User Registration:**
   - Signup endpoint enables legitimate user creation
   - All passwords automatically secured
   - Validation prevents common registration issues

### Testing the Fix

#### Test Login with Existing Users:
```bash
# After restarting the application (to re-seed with hashed passwords)
curl -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}'
```

Expected Response:
```json
{
    "token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

#### Test Signup:
```bash
curl -X POST http://localhost:8080/api/auth/signup \
  -H 'Content-Type: application/json' \
  -d '{"username":"testuser","password":"testpass123","email":"test@example.com"}'
```

Expected Response:
```json
{
    "status": "user created successfully",
    "username": "testuser"
}
```

#### Verify Password Hash in Database:
```sql
-- Access H2 Console at http://localhost:8080/h2-console
-- JDBC URL: jdbc:h2:mem:apilab
SELECT username, password FROM APP_USER;
```

Expected Result:
- Passwords should look like: `$2a$10$Xy9zA...` (BCrypt hash)
- NOT plaintext like: `alice123`

### Remaining Vulnerabilities (Future Tasks)

While Task 1 fixes password storage, the following security issues remain:
- No rate limiting on login endpoint (brute force vulnerable)
- No account lockout mechanism
- No multi-factor authentication (MFA)
- No password complexity requirements
- No password history or rotation policy
- Session tokens have long TTL (30 days)

These will be addressed in subsequent tasks.

---

### Files Modified Summary

1. ✅ `SecurityConfig.java` - Added PasswordEncoder bean
2. ✅ `DataSeeder.java` - Hash passwords during seeding
3. ✅ `AuthController.java` - BCrypt verification + signup endpoint
4. ✅ `AppUser.java` - Updated documentation

### Migration Notes

**Important:** If the database already contains users with plaintext passwords, you need to either:

1. **Option 1: Reset Database (H2 in-memory)**
   - Simply restart the application
   - H2 in-memory database will be recreated with hashed passwords

2. **Option 2: Migration Script (for production databases)**
   ```java
   // Run once to migrate existing users
   List<AppUser> users = userRepository.findAll();
   for (AppUser user : users) {
       if (!user.getPassword().startsWith("$2a$")) {
           user.setPassword(passwordEncoder.encode(user.getPassword()));
           userRepository.save(user);
       }
   }
   ```

---

**Fix Completed:** ✅ Task 1 - Replace Plaintext Passwords with BCrypt  
**Date:** October 25, 2025  
**Security Level:** HIGH PRIORITY - Critical authentication vulnerability fixed
