# Security Fixes Documentation

## Table of Contents
1. [Task 1: Replace Plaintext Passwords with BCrypt](#task-1-replace-plaintext-passwords-with-bcrypt)
2. [Task 2: Tighten SecurityFilterChain](#task-2-tighten-securityfilterchain)
3. [Task 3: Enforce Ownership in Controllers](#task-3-enforce-ownership-in-controllers)
4. [Task 4: Implement DTOs to Control Data Exposure](#task-4-implement-dtos-to-control-data-exposure)
5. [Task 5: Add Rate Limiting](#task-5-add-rate-limiting)
6. [Task 6: Prevent Mass Assignment](#task-6-prevent-mass-assignment)

---

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

---

## Task 2: Tighten SecurityFilterChain

### Overview
Fixed the API7 Security Misconfiguration vulnerability by removing overly permissive authentication rules and implementing proper JWT token validation. The original configuration allowed unauthenticated access to all GET endpoints, enabling data scraping and unauthorized access.

### Vulnerability Description
**OWASP API Security Category:** API7 - Security Misconfiguration

**Original Issues:**
1. **Overly Permissive GET Access:** All GET requests to `/api/**` were permitted without authentication
   - Anonymous users could access sensitive endpoints like `/api/users/{id}`, `/api/accounts/{id}/balance`
   - Data scraping was possible on all GET endpoints
   - No authentication required for viewing user data

2. **Silent JWT Error Handling:** Invalid or expired JWT tokens were silently ignored
   - Failed JWT validation continued processing as anonymous user
   - No error response sent to client
   - Security failures were invisible to both users and administrators

3. **Broad Auth Endpoint Permissions:** Entire `/api/auth/**` path was public
   - Even hypothetical admin auth endpoints would be public
   - No granular control over which auth endpoints are public

### Changes Made

#### 1. SecurityConfig.java - filterChain() Method
**Location:** `src/main/java/edu/nu/owaspapivulnlab/config/SecurityConfig.java`

**Changes Made:**

##### a) Removed Dangerous permitAll on GET Requests
**Before (VULNERABLE):**
```java
http.authorizeHttpRequests(reg -> reg
    .requestMatchers("/api/auth/**", "/h2-console/**").permitAll()
    // VULNERABILITY: broad permitAll on GET allows data scraping
    .requestMatchers(HttpMethod.GET, "/api/**").permitAll()
    .requestMatchers("/api/admin/**").hasRole("ADMIN")
    .anyRequest().authenticated()
);
```

**After (SECURE):**
```java
http.authorizeHttpRequests(reg -> reg
    // FIX(Task 2): Only specific auth endpoints are public
    .requestMatchers("/api/auth/login", "/api/auth/signup").permitAll()
    .requestMatchers("/h2-console/**").permitAll()
    
    // FIX(Task 2): Admin endpoints require ADMIN role
    .requestMatchers("/api/admin/**").hasRole("ADMIN")
    
    // FIX(Task 2): All other /api/** endpoints require authentication
    .requestMatchers("/api/**").authenticated()
    
    .anyRequest().authenticated()
);
```

**Security Improvements:**
- ✅ Removed `HttpMethod.GET` permitAll rule completely
- ✅ Changed `/api/auth/**` wildcard to specific endpoints: `/api/auth/login` and `/api/auth/signup`
- ✅ All `/api/**` endpoints now require authentication by default
- ✅ Proper order of matchers: specific rules before general rules
- ✅ Admin endpoints explicitly require ADMIN role

**Impact:**
- Anonymous users can no longer access GET endpoints
- All user data, account data, and other resources require authentication
- Only login and signup are publicly accessible
- Data scraping attacks are prevented

---

#### 2. SecurityConfig.java - JwtFilter Class
**Location:** `src/main/java/edu/nu/owaspapivulnlab/config/SecurityConfig.java`

**Changes Made:**

##### a) Proper JWT Error Handling

**Before (VULNERABLE):**
```java
try {
    Claims c = Jwts.parserBuilder().setSigningKey(secret.getBytes()).build()
            .parseClaimsJws(token).getBody();
    String user = c.getSubject();
    String role = (String) c.get("role");
    UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(user, null,
            role != null ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role)) : Collections.emptyList());
    SecurityContextHolder.getContext().setAuthentication(authn);
} catch (JwtException e) {
    // VULNERABILITY: swallow errors; continue as anonymous (API7)
}
chain.doFilter(request, response);
```

**After (SECURE):**
```java
try {
    // FIX(Task 2): Validate JWT token and extract claims
    Claims c = Jwts.parserBuilder().setSigningKey(secret.getBytes()).build()
            .parseClaimsJws(token).getBody();
    String user = c.getSubject();
    String role = (String) c.get("role");
    
    // Set authentication in security context
    UsernamePasswordAuthenticationToken authn = new UsernamePasswordAuthenticationToken(user, null,
            role != null ? Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role)) : Collections.emptyList());
    SecurityContextHolder.getContext().setAuthentication(authn);
    
} catch (ExpiredJwtException e) {
    // FIX(Task 2): Reject expired tokens with proper error response
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setContentType("application/json");
    response.getWriter().write("{\"error\":\"Token expired\"}");
    return; // Stop the filter chain - don't continue as anonymous
    
} catch (JwtException e) {
    // FIX(Task 2): Reject invalid tokens with proper error response
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setContentType("application/json");
    response.getWriter().write("{\"error\":\"Invalid or malformed token\"}");
    return; // Stop the filter chain - don't continue as anonymous
}
chain.doFilter(request, response);
```

**Security Improvements:**
- ✅ Separate handling for `ExpiredJwtException` with specific error message
- ✅ Generic `JwtException` catch for other JWT validation failures
- ✅ Returns HTTP 401 Unauthorized status code
- ✅ Provides clear JSON error messages to clients
- ✅ Stops filter chain execution with `return` statement
- ✅ No longer continues processing as anonymous user

**Error Responses:**

For expired tokens:
```json
{
  "error": "Token expired"
}
```

For invalid/malformed tokens:
```json
{
  "error": "Invalid or malformed token"
}
```

**Impact:**
- Failed JWT validation now properly rejects requests
- Clients receive clear feedback about authentication failures
- Security issues are visible and logged
- Prevents unauthorized access via malformed tokens
- Improves API security posture and monitoring

---

#### 3. Code Cleanup
**Location:** `src/main/java/edu/nu/owaspapivulnlab/config/SecurityConfig.java`

**Changes:**
- Removed unused import: `org.springframework.http.HttpMethod`
- Added comprehensive FIX(Task 2) comments throughout the code

---

### Security Benefits

1. **Enforced Authentication:**
   - All API endpoints (except login/signup) now require valid JWT tokens
   - Eliminates anonymous data access
   - Prevents unauthorized information disclosure

2. **Explicit Error Handling:**
   - Invalid tokens receive clear 401 Unauthorized responses
   - Expired tokens get specific "Token expired" messages
   - Failed authentication attempts are visible and can be logged/monitored

3. **Principle of Least Privilege:**
   - Only absolutely necessary endpoints are public (login, signup)
   - Admin endpoints explicitly require ADMIN role
   - Default-deny policy for all other endpoints

4. **Defense in Depth:**
   - JWT validation at filter level
   - Spring Security authorization rules at endpoint level
   - Multiple layers of security checks

5. **Improved Security Visibility:**
   - Authentication failures are no longer silent
   - Clear error messages aid in debugging and monitoring
   - Security events can be logged and audited

### Testing the Fix

#### Test 1: Verify Unauthenticated Access is Blocked

**Test accessing user endpoint without token:**
```powershell
curl -X GET http://localhost:8080/api/users/1
```

**Expected Response:**
```
HTTP 401 Unauthorized
(Spring Security default error page or redirect to login)
```

**Test accessing account balance without token:**
```powershell
curl -X GET http://localhost:8080/api/accounts/1/balance
```

**Expected Response:**
```
HTTP 401 Unauthorized
```

---

#### Test 2: Verify Public Endpoints Still Work

**Test login endpoint (should work):**
```powershell
curl -X POST http://localhost:8080/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"username":"alice","password":"alice123"}'
```

**Expected Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9..."
}
```

**Test signup endpoint (should work):**
```powershell
curl -X POST http://localhost:8080/api/auth/signup `
  -H "Content-Type: application/json" `
  -d '{"username":"newuser","password":"pass123","email":"test@example.com"}'
```

**Expected Response:**
```json
{
  "status": "user created successfully",
  "username": "newuser"
}
```

---

#### Test 3: Verify Authenticated Access Works

**Get valid token:**
```powershell
$response = curl -X POST http://localhost:8080/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"username":"alice","password":"alice123"}' | ConvertFrom-Json

$token = $response.token
```

**Test accessing endpoint with valid token:**
```powershell
curl -X GET http://localhost:8080/api/accounts/mine `
  -H "Authorization: Bearer $token"
```

**Expected Response:**
```json
[
  {
    "id": 1,
    "ownerUserId": 1,
    "iban": "PK00-ALICE",
    "balance": 1000.0
  }
]
```

---

#### Test 4: Verify Invalid Token is Rejected

**Test with malformed token:**
```powershell
curl -X GET http://localhost:8080/api/accounts/mine `
  -H "Authorization: Bearer invalid.token.here"
```

**Expected Response:**
```
HTTP 401 Unauthorized
Content-Type: application/json

{
  "error": "Invalid or malformed token"
}
```

---

#### Test 5: Verify Admin Endpoint Protection

**Test admin endpoint as regular user:**
```powershell
# Login as alice (USER role)
$response = curl -X POST http://localhost:8080/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"username":"alice","password":"alice123"}' | ConvertFrom-Json

# Try to access admin endpoint
curl -X GET http://localhost:8080/api/admin/metrics `
  -H "Authorization: Bearer $($response.token)"
```

**Expected Response:**
```
HTTP 403 Forbidden
```

**Test admin endpoint as admin user:**
```powershell
# Login as bob (ADMIN role)
$response = curl -X POST http://localhost:8080/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"username":"bob","password":"bob123"}' | ConvertFrom-Json

# Access admin endpoint
curl -X GET http://localhost:8080/api/admin/metrics `
  -H "Authorization: Bearer $($response.token)"
```

**Expected Response:**
```json
{
  "uptimeMs": 12345,
  "javaVersion": "17.0.x",
  "threads": 25
}
```

---

### Comparison: Before vs After

| Scenario | Before (Vulnerable) | After (Fixed) |
|----------|-------------------|---------------|
| GET /api/users/1 (no token) | ✅ Allowed | ❌ 401 Unauthorized |
| GET /api/accounts/1/balance (no token) | ✅ Allowed | ❌ 401 Unauthorized |
| POST /api/auth/login | ✅ Allowed | ✅ Allowed |
| POST /api/auth/signup | ✅ Allowed | ✅ Allowed |
| Invalid JWT token | ⚠️ Silent failure → Anonymous | ❌ 401 with error message |
| Expired JWT token | ⚠️ Silent failure → Anonymous | ❌ 401 "Token expired" |
| GET /api/admin/metrics (USER role) | ❌ Blocked | ❌ 403 Forbidden |
| GET /api/admin/metrics (ADMIN role) | ✅ Allowed | ✅ Allowed |
| Any /api/** with valid token | ✅ Allowed | ✅ Allowed |

---

### Remaining Vulnerabilities (Future Tasks)

While Task 2 fixes authorization and authentication enforcement, the following issues remain:

1. **No Rate Limiting** - Endpoints are still vulnerable to brute force and DoS attacks (Task 5)
2. **Weak JWT Configuration** - Token TTL is still too long, weak secret (Task 7)
3. **BOLA/IDOR Issues** - Controllers don't verify resource ownership (Task 3)
4. **Excessive Data Exposure** - Responses still include sensitive fields (Task 4)
5. **Mass Assignment** - Input validation and DTOs needed (Task 6)

These will be addressed in subsequent tasks.

---

### Files Modified Summary

1. ✅ `SecurityConfig.java` - Tightened authorization rules and fixed JWT error handling

### Architecture Changes

**Before:**
```
Request → JWT Filter (silent failure) → permitAll GET /api/** → Controller
                ↓
           Anonymous Access Allowed
```

**After:**
```
Request → JWT Filter (rejects invalid) → authenticated /api/** → Controller
                ↓                               ↓
         401 if invalid              403 if no permission
```

---

**Fix Completed:** ✅ Task 2 - Tighten SecurityFilterChain  
**Date:** October 26, 2025  
**Security Level:** HIGH PRIORITY - Critical authorization and authentication vulnerability fixed

---

## Task 3: Enforce Ownership in Controllers

### Overview
Fixed the API1 Broken Object Level Authorization (BOLA/IDOR) vulnerability by implementing ownership verification in all controllers. Users can now only access and modify their own resources, preventing unauthorized access to other users' data.

### Vulnerability Description
**OWASP API Security Category:** API1 - Broken Object Level Authorization (BOLA/IDOR)

**Original Issues:**

1. **AccountController.balance()**: Any authenticated user could view any account balance by ID
   - Example: User with ID 1 could access `/api/accounts/2/balance` (User 2's account)
   - No verification that the account belongs to the authenticated user

2. **AccountController.transfer()**: Any authenticated user could transfer money from any account
   - Example: User could transfer money from someone else's account
   - No ownership verification before performing transfers
   - No input validation on transfer amounts (negative, zero, excessive)

3. **UserController.get()**: Any authenticated user could view any other user's profile
   - Example: User could access `/api/users/2` to view another user's details
   - Exposed sensitive information like passwords, roles, admin flags

4. **UserController.delete()**: Regular users could delete any user account
   - No admin privilege check
   - Users could delete administrators or other users
   - No protection against self-deletion

### Changes Made

#### 1. AccountController.java

##### a) balance() Method - Added Ownership Verification

**Location:** `src/main/java/edu/nu/owaspapivulnlab/web/AccountController.java`

**Before (VULNERABLE):**
```java
@GetMapping("/{id}/balance")
public Double balance(@PathVariable Long id) {
    Account a = accounts.findById(id).orElseThrow(() -> new RuntimeException("Account not found"));
    return a.getBalance();
}
```

**After (SECURE):**
```java
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
```

**Security Improvements:**
- ✅ Injects `Authentication` parameter to get authenticated user
- ✅ Verifies user is authenticated (returns 401 if not)
- ✅ Retrieves authenticated user from database via username
- ✅ Verifies account ownership by comparing `ownerUserId` with current user's ID
- ✅ Returns 403 Forbidden if user tries to access another's account
- ✅ Returns structured JSON response instead of raw Double

**Example Attack Prevented:**
```bash
# Alice (user ID 1) tries to view Bob's account (ID 2)
curl -H "Authorization: Bearer $ALICE_TOKEN" http://localhost:8080/api/accounts/2/balance
# Before: Shows Bob's balance ❌
# After: 403 {"error":"Access denied - you can only view your own accounts"} ✅
```

---

##### b) transfer() Method - Added Ownership & Input Validation

**Location:** `src/main/java/edu/nu/owaspapivulnlab/web/AccountController.java`

**Before (VULNERABLE):**
```java
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
```

**After (SECURE):**
```java
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
```

**Security Improvements:**
- ✅ Authentication verification (401 if not authenticated)
- ✅ **Task 9: Input validation for amount (must be positive)**
- ✅ **Task 9: Maximum transfer limit (1,000,000)**
- ✅ Ownership verification (403 if accessing another's account)
- ✅ **Task 9: Sufficient balance check**
- ✅ Structured response with transfer details

**Example Attacks Prevented:**

1. **BOLA Attack:**
```bash
# Alice tries to transfer from Bob's account
curl -X POST "http://localhost:8080/api/accounts/2/transfer?amount=100" \
  -H "Authorization: Bearer $ALICE_TOKEN"
# Before: Transfers money from Bob's account ❌
# After: 403 {"error":"Access denied - you can only transfer from your own accounts"} ✅
```

2. **Negative Transfer Attack:**
```bash
# Try to add money via negative transfer
curl -X POST "http://localhost:8080/api/accounts/1/transfer?amount=-1000" \
  -H "Authorization: Bearer $ALICE_TOKEN"
# Before: Adds money to account ❌
# After: 400 {"error":"Amount must be positive"} ✅
```

3. **Overdraft Attack:**
```bash
# Try to transfer more than available balance
curl -X POST "http://localhost:8080/api/accounts/1/transfer?amount=999999" \
  -H "Authorization: Bearer $ALICE_TOKEN"
# Before: Creates negative balance ❌
# After: 400 {"error":"Insufficient balance","available":"1000.0"} ✅
```

---

#### 2. UserController.java

##### a) get() Method - Added Ownership Verification

**Location:** `src/main/java/edu/nu/owaspapivulnlab/web/UserController.java`

**Before (VULNERABLE):**
```java
@GetMapping("/{id}")
public AppUser get(@PathVariable Long id) {
    return users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
}
```

**After (SECURE):**
```java
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
```

**Security Improvements:**
- ✅ Authentication verification
- ✅ Ownership verification: users can only view their own profile
- ✅ Admin privilege: admins can view any profile
- ✅ 403 Forbidden for unauthorized access
- ✅ Note: Still returns full entity (Task 4 will fix data exposure)

**Example Attack Prevented:**
```bash
# Regular user Alice tries to view Bob's profile
curl -H "Authorization: Bearer $ALICE_TOKEN" http://localhost:8080/api/users/2
# Before: Shows Bob's full profile including password ❌
# After: 403 {"error":"Access denied - you can only view your own profile"} ✅
```

---

##### b) delete() Method - Added Admin-Only Authorization

**Location:** `src/main/java/edu/nu/owaspapivulnlab/web/UserController.java`

**Before (VULNERABLE):**
```java
@DeleteMapping("/{id}")
public ResponseEntity<?> delete(@PathVariable Long id) {
    users.deleteById(id);
    Map<String, String> response = new HashMap<>();
    response.put("status", "deleted");
    return ResponseEntity.ok(response);
}
```

**After (SECURE):**
```java
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
    
    // FIX(Task 3): Only admins can delete users
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
```

**Security Improvements:**
- ✅ Authentication verification
- ✅ **Admin-only access** (prevents privilege escalation)
- ✅ **Self-deletion prevention** (admins can't delete themselves)
- ✅ Existence check before deletion (proper 404 handling)
- ✅ Detailed error messages for different scenarios

**Example Attacks Prevented:**

1. **Regular User Deletion Attack:**
```bash
# Regular user Alice tries to delete Bob
curl -X DELETE http://localhost:8080/api/users/2 \
  -H "Authorization: Bearer $ALICE_TOKEN"
# Before: Deletes Bob ❌
# After: 403 {"error":"Access denied - admin privileges required"} ✅
```

2. **Self-Deletion Attack:**
```bash
# Admin Bob tries to delete himself
curl -X DELETE http://localhost:8080/api/users/2 \
  -H "Authorization: Bearer $BOB_ADMIN_TOKEN"
# Before: Deletes the admin account ❌
# After: 400 {"error":"You cannot delete your own account"} ✅
```

---

### Security Benefits

1. **Broken Object Level Authorization (BOLA) Fixed:**
   - Users can only access resources they own
   - Ownership verification on every sensitive operation
   - Prevents horizontal privilege escalation

2. **Input Validation (Partial Task 9):**
   - Transfer amounts must be positive
   - Maximum transfer limits enforced
   - Sufficient balance checks prevent overdrafts
   - Prevents negative balance exploits

3. **Function Level Authorization:**
   - Admin privileges verified for privileged operations
   - Prevents regular users from performing admin actions
   - Prevents vertical privilege escalation

4. **Defense in Depth:**
   - Multiple security checks (authentication → ownership → authorization)
   - Proper HTTP status codes (401, 403, 400, 404)
   - Clear error messages for security issues

5. **Self-Protection:**
   - Admins cannot delete themselves (operational safety)
   - Existence checks prevent errors

### Testing the Fix

#### Test 1: Verify BOLA Protection on Account Balance

**Setup:**
```powershell
# Login as Alice
$alice = (curl -X POST http://localhost:8080/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"username":"alice","password":"alice123"}' | ConvertFrom-Json)

# Login as Bob
$bob = (curl -X POST http://localhost:8080/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"username":"bob","password":"bob123"}' | ConvertFrom-Json)
```

**Test Alice accessing her own account (should work):**
```powershell
curl -X GET http://localhost:8080/api/accounts/1/balance `
  -H "Authorization: Bearer $($alice.token)"
```

**Expected Response:**
```json
{
  "accountId": 1,
  "balance": 1000.0
}
```

**Test Alice accessing Bob's account (should fail):**
```powershell
curl -X GET http://localhost:8080/api/accounts/2/balance `
  -H "Authorization: Bearer $($alice.token)"
```

**Expected Response:**
```
HTTP 403 Forbidden
{
  "error": "Access denied - you can only view your own accounts"
}
```

---

#### Test 2: Verify BOLA Protection on Transfers

**Test Alice transferring from her account (should work):**
```powershell
curl -X POST "http://localhost:8080/api/accounts/1/transfer?amount=50" `
  -H "Authorization: Bearer $($alice.token)"
```

**Expected Response:**
```json
{
  "status": "ok",
  "remaining": 950.0,
  "transferred": 50.0
}
```

**Test Alice transferring from Bob's account (should fail):**
```powershell
curl -X POST "http://localhost:8080/api/accounts/2/transfer?amount=100" `
  -H "Authorization: Bearer $($alice.token)"
```

**Expected Response:**
```
HTTP 403 Forbidden
{
  "error": "Access denied - you can only transfer from your own accounts"
}
```

---

#### Test 3: Verify Input Validation on Transfers

**Test negative amount:**
```powershell
curl -X POST "http://localhost:8080/api/accounts/1/transfer?amount=-100" `
  -H "Authorization: Bearer $($alice.token)"
```

**Expected Response:**
```
HTTP 400 Bad Request
{
  "error": "Amount must be positive"
}
```

**Test excessive amount:**
```powershell
curl -X POST "http://localhost:8080/api/accounts/1/transfer?amount=2000000" `
  -H "Authorization: Bearer $($alice.token)"
```

**Expected Response:**
```
HTTP 400 Bad Request
{
  "error": "Amount exceeds maximum transfer limit of 1,000,000"
}
```

**Test insufficient balance:**
```powershell
curl -X POST "http://localhost:8080/api/accounts/1/transfer?amount=5000" `
  -H "Authorization: Bearer $($alice.token)"
```

**Expected Response:**
```
HTTP 400 Bad Request
{
  "error": "Insufficient balance",
  "available": "1000.0"
}
```

---

#### Test 4: Verify User Profile Access Control

**Test Alice viewing her own profile (should work):**
```powershell
curl -X GET http://localhost:8080/api/users/1 `
  -H "Authorization: Bearer $($alice.token)"
```

**Expected Response:**
```json
{
  "id": 1,
  "username": "alice",
  "email": "alice@cydea.tech",
  "role": "USER",
  "isAdmin": false
  // Note: password still exposed (Task 4 will fix)
}
```

**Test Alice viewing Bob's profile (should fail):**
```powershell
curl -X GET http://localhost:8080/api/users/2 `
  -H "Authorization: Bearer $($alice.token)"
```

**Expected Response:**
```
HTTP 403 Forbidden
{
  "error": "Access denied - you can only view your own profile"
}
```

**Test Admin Bob viewing Alice's profile (should work):**
```powershell
curl -X GET http://localhost:8080/api/users/1 `
  -H "Authorization: Bearer $($bob.token)"
```

**Expected Response:**
```json
{
  "id": 1,
  "username": "alice",
  ...
}
```

---

#### Test 5: Verify Delete Authorization

**Test regular user Alice deleting Bob (should fail):**
```powershell
curl -X DELETE http://localhost:8080/api/users/2 `
  -H "Authorization: Bearer $($alice.token)"
```

**Expected Response:**
```
HTTP 403 Forbidden
{
  "error": "Access denied - admin privileges required"
}
```

**Test admin Bob deleting himself (should fail):**
```powershell
curl -X DELETE http://localhost:8080/api/users/2 `
  -H "Authorization: Bearer $($bob.token)"
```

**Expected Response:**
```
HTTP 400 Bad Request
{
  "error": "You cannot delete your own account"
}
```

**Test admin Bob deleting Alice (should work):**
```powershell
curl -X DELETE http://localhost:8080/api/users/1 `
  -H "Authorization: Bearer $($bob.token)"
```

**Expected Response:**
```json
{
  "status": "deleted",
  "message": "User successfully deleted"
}
```

---

### Comparison: Before vs After

| Scenario | Before (Vulnerable) | After (Fixed) |
|----------|-------------------|---------------|
| Alice views Alice's account balance | ✅ Allowed | ✅ Allowed |
| Alice views Bob's account balance | ✅ Allowed ❌ | ❌ 403 Forbidden ✅ |
| Alice transfers from Alice's account | ✅ Allowed | ✅ Allowed |
| Alice transfers from Bob's account | ✅ Allowed ❌ | ❌ 403 Forbidden ✅ |
| Negative transfer amount | ✅ Allowed ❌ | ❌ 400 Bad Request ✅ |
| Transfer > 1,000,000 | ✅ Allowed ❌ | ❌ 400 Bad Request ✅ |
| Transfer > balance | ✅ Allowed ❌ | ❌ 400 Bad Request ✅ |
| Alice views Alice's profile | ✅ Allowed | ✅ Allowed |
| Alice views Bob's profile | ✅ Allowed ❌ | ❌ 403 Forbidden ✅ |
| Admin Bob views Alice's profile | ✅ Allowed | ✅ Allowed |
| Alice deletes Bob | ✅ Allowed ❌ | ❌ 403 Forbidden ✅ |
| Admin Bob deletes Alice | ✅ Allowed | ✅ Allowed |
| Admin Bob deletes himself | ✅ Allowed ❌ | ❌ 400 Bad Request ✅ |

---

### Remaining Vulnerabilities (Future Tasks)

While Task 3 fixes ownership and authorization, the following issues remain:

1. **Excessive Data Exposure** - User profiles still return sensitive fields like password, role, isAdmin (Task 4)
2. **No Rate Limiting** - Still vulnerable to brute force and DoS (Task 5)
3. **Mass Assignment** - User creation still vulnerable (Task 6)
4. **Weak JWT** - Token configuration still needs hardening (Task 7)
5. **Verbose Errors** - Error messages too detailed for production (Task 8)

These will be addressed in subsequent tasks.

---

### Files Modified Summary

1. ✅ `AccountController.java`
   - `balance()` - Added ownership verification
   - `transfer()` - Added ownership verification + input validation

2. ✅ `UserController.java`
   - `get()` - Added ownership verification (users/admins)
   - `delete()` - Added admin-only authorization + self-deletion prevention

---

**Fix Completed:** ✅ Task 3 - Enforce Ownership in Controllers  
**Date:** October 26, 2025  
**Security Level:** CRITICAL - BOLA/IDOR vulnerability fixed, prevents unauthorized resource access

---

## Task 4: Implement DTOs to Control Data Exposure

### Overview
Fixed the API3 Excessive Data Exposure vulnerability by implementing Data Transfer Objects (DTOs) throughout the application. Controllers now return DTOs instead of raw entity objects, preventing exposure of sensitive fields like passwords, roles, and internal IDs.

### Vulnerability Description
**OWASP API Security Category:** API3 - Excessive Data Exposure & API6 - Mass Assignment (partial)

**Original Issues:**

1. **Password Hash Exposure**: User endpoints returned full `AppUser` entities including BCrypt password hashes
   - Example: `GET /api/users/1` returned `{"password":"$2a$10$xyz..."}`
   - Even hashed passwords should never be exposed to clients

2. **Role and Admin Flag Exposure**: Internal authorization details exposed to clients
   - Endpoints returned `role` and `isAdmin` fields
   - Clients don't need to know internal authorization details
   - Information disclosure could aid attackers in privilege escalation attempts

3. **Internal ID Exposure**: Foreign keys and internal relationships exposed
   - `Account` entity returned `ownerUserId` field
   - Exposes database structure and relationships
   - Not relevant for API consumers

4. **Mass Assignment Vulnerability**: Direct entity binding allowed privilege escalation
   - `POST /api/users` accepted full `AppUser` entity
   - Clients could set `role="ADMIN"` and `isAdmin=true`
   - No input validation or server-side control

### Changes Made

#### 1. Created DTO Package Structure

**New Directory:** `src/main/java/edu/nu/owaspapivulnlab/dto/`

Created four new DTO classes to handle data transfer safely:

---

#### 2. UserResponseDTO.java

**Location:** `src/main/java/edu/nu/owaspapivulnlab/dto/UserResponseDTO.java`

**Purpose:** Safe representation of user data for API responses

**Code:**
```java
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponseDTO {
    private Long id;
    private String username;
    private String email;
    
    // FIX(Task 4): Sensitive fields intentionally excluded:
    // - password: Never expose password hashes
    // - role: Internal authorization detail, not for client consumption
    // - isAdmin: Internal flag, should not be exposed to clients
}
```

**Fields Included:**
- ✅ `id` - Public identifier
- ✅ `username` - Public display name
- ✅ `email` - Contact information

**Fields Excluded (Security):**
- ❌ `password` - BCrypt hash, should never be exposed
- ❌ `role` - Internal authorization detail
- ❌ `isAdmin` - Internal privilege flag

**Impact:** Users can no longer see password hashes, roles, or admin flags in API responses

---

#### 3. AccountResponseDTO.java

**Location:** `src/main/java/edu/nu/owaspapivulnlab/dto/AccountResponseDTO.java`

**Purpose:** Safe representation of account data for API responses

**Code:**
```java
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
}
```

**Fields Included:**
- ✅ `id` - Account identifier
- ✅ `iban` - Account number
- ✅ `balance` - Current balance

**Fields Excluded (Security):**
- ❌ `ownerUserId` - Internal foreign key, database implementation detail

**Impact:** Clients no longer see internal database relationships

---

#### 4. CreateUserRequest.java

**Location:** `src/main/java/edu/nu/owaspapivulnlab/dto/CreateUserRequest.java`

**Purpose:** Safe input DTO for user creation, prevents mass assignment

**Code:**
```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateUserRequest {
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;
    
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;
    
    @Email(message = "Valid email is required")
    @NotBlank(message = "Email is required")
    private String email;
    
    // FIX(Task 6): Dangerous fields intentionally excluded:
    // - role: Server assigns default "USER" role
    // - isAdmin: Server controls admin privileges, not client
}
```

**Fields Accepted:**
- ✅ `username` - With validation (3-50 chars)
- ✅ `password` - With validation (min 8 chars)
- ✅ `email` - With validation (valid email format)

**Fields Rejected (Security):**
- ❌ `role` - Server-controlled, always "USER" for new accounts
- ❌ `isAdmin` - Server-controlled, always false for new accounts

**Impact:** 
- Prevents privilege escalation via mass assignment
- Clients cannot create admin accounts
- Server has full control over authorization

---

#### 5. DTOMapper.java

**Location:** `src/main/java/edu/nu/owaspapivulnlab/dto/DTOMapper.java`

**Purpose:** Centralized utility class for entity-to-DTO conversions

**Methods:**

```java
public class DTOMapper {
    // Convert single user entity to DTO
    public static UserResponseDTO toUserDTO(AppUser user) {
        return UserResponseDTO.builder()
            .id(user.getId())
            .username(user.getUsername())
            .email(user.getEmail())
            .build();
    }
    
    // Convert list of users to list of DTOs
    public static List<UserResponseDTO> toUserDTOList(List<AppUser> users) {
        return users.stream()
            .map(DTOMapper::toUserDTO)
            .collect(Collectors.toList());
    }
    
    // Convert single account entity to DTO
    public static AccountResponseDTO toAccountDTO(Account account) {
        return AccountResponseDTO.builder()
            .id(account.getId())
            .iban(account.getIban())
            .balance(account.getBalance())
            .build();
    }
    
    // Convert list of accounts to list of DTOs
    public static List<AccountResponseDTO> toAccountDTOList(List<Account> accounts) {
        return accounts.stream()
            .map(DTOMapper::toAccountDTO)
            .collect(Collectors.toList());
    }
}
```

**Benefits:**
- ✅ Centralized conversion logic
- ✅ Consistent data transformation across all controllers
- ✅ Easy to maintain and update
- ✅ Null-safe implementations
- ✅ Stream API for efficient list conversions

---

#### 6. AccountController.java Updates

**Location:** `src/main/java/edu/nu/owaspapivulnlab/web/AccountController.java`

##### a) Added DTO Imports

```java
import edu.nu.owaspapivulnlab.dto.AccountResponseDTO;
import edu.nu.owaspapivulnlab.dto.DTOMapper;
import java.util.List;
```

##### b) Updated mine() Method

**Before (VULNERABLE):**
```java
@GetMapping("/mine")
public Object mine(Authentication auth) {
    AppUser me = users.findByUsername(auth != null ? auth.getName() : "anonymous").orElse(null);
    return me == null ? Collections.emptyList() : accounts.findByOwnerUserId(me.getId());
}
```

**After (SECURE):**
```java
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
    List<Account> userAccounts = accounts.findByOwnerUserId(me.getId());
    List<AccountResponseDTO> accountDTOs = DTOMapper.toAccountDTOList(userAccounts);
    
    return ResponseEntity.ok(accountDTOs);
}
```

**Security Improvements:**
- ✅ Authentication verification added
- ✅ Returns `AccountResponseDTO` instead of raw `Account` entities
- ✅ Hides `ownerUserId` from response
- ✅ Proper error handling with structured responses

**Response Comparison:**

Before:
```json
[
  {
    "id": 1,
    "ownerUserId": 1,  // ❌ Internal foreign key exposed
    "iban": "PK00-ALICE",
    "balance": 1000.0
  }
]
```

After:
```json
[
  {
    "id": 1,
    "iban": "PK00-ALICE",
    "balance": 1000.0
    // ✅ ownerUserId no longer exposed
  }
]
```

---

#### 7. UserController.java Updates

**Location:** `src/main/java/edu/nu/owaspapivulnlab/web/UserController.java`

##### a) Added DTO Imports and PasswordEncoder

```java
import org.springframework.security.crypto.password.PasswordEncoder;
import edu.nu.owaspapivulnlab.dto.UserResponseDTO;
import edu.nu.owaspapivulnlab.dto.CreateUserRequest;
import edu.nu.owaspapivulnlab.dto.DTOMapper;

// Injected PasswordEncoder for secure user creation
private final PasswordEncoder passwordEncoder;
```

##### b) Updated get() Method

**Before (VULNERABLE):**
```java
@GetMapping("/{id}")
public ResponseEntity<?> get(@PathVariable Long id, Authentication auth) {
    // ... authorization checks ...
    AppUser user = users.findById(id).orElseThrow(...);
    return ResponseEntity.ok(user);  // ❌ Exposes password, role, isAdmin
}
```

**After (SECURE):**
```java
@GetMapping("/{id}")
public ResponseEntity<?> get(@PathVariable Long id, Authentication auth) {
    // ... authorization checks ...
    AppUser user = users.findById(id).orElseThrow(...);
    
    // FIX(Task 4): Return DTO instead of full entity
    UserResponseDTO userDTO = DTOMapper.toUserDTO(user);
    return ResponseEntity.ok(userDTO);  // ✅ Only safe fields
}
```

**Response Comparison:**

Before:
```json
{
  "id": 1,
  "username": "alice",
  "password": "$2a$10$xYzAbC...",  // ❌ Password hash exposed
  "email": "alice@cydea.tech",
  "role": "USER",  // ❌ Internal role exposed
  "isAdmin": false  // ❌ Internal flag exposed
}
```

After:
```json
{
  "id": 1,
  "username": "alice",
  "email": "alice@cydea.tech"
  // ✅ Password, role, and isAdmin no longer exposed
}
```

---

##### c) Updated create() Method - Prevents Mass Assignment

**Before (VULNERABLE):**
```java
@PostMapping
public AppUser create(@Valid @RequestBody AppUser body) {
    return users.save(body);  // ❌ Client can set role and isAdmin
}
```

**After (SECURE):**
```java
@PostMapping
public ResponseEntity<?> create(@Valid @RequestBody CreateUserRequest request) {
    // Check if username already exists
    if (users.findByUsername(request.getUsername()).isPresent()) {
        Map<String, String> error = new HashMap<>();
        error.put("error", "Username already exists");
        return ResponseEntity.status(400).body(error);
    }
    
    // FIX(Task 6): Server assigns role and admin status, NOT the client
    AppUser newUser = AppUser.builder()
        .username(request.getUsername())
        .password(passwordEncoder.encode(request.getPassword()))
        .email(request.getEmail())
        .role("USER")  // ✅ Server controls role
        .isAdmin(false)  // ✅ Server controls admin flag
        .build();
    
    AppUser savedUser = users.save(newUser);
    
    // FIX(Task 4): Return DTO instead of full entity
    UserResponseDTO responseDTO = DTOMapper.toUserDTO(savedUser);
    return ResponseEntity.status(201).body(responseDTO);
}
```

**Security Improvements:**
- ✅ Uses `CreateUserRequest` DTO (no role/isAdmin fields)
- ✅ Server always assigns `role="USER"`
- ✅ Server always sets `isAdmin=false`
- ✅ Password is hashed before storage
- ✅ Returns DTO (doesn't echo back hashed password)
- ✅ Validates username uniqueness
- ✅ Proper 201 Created status code

**Attack Prevention:**

Before (Mass Assignment Attack):
```bash
# Attacker tries to create admin account
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username":"hacker",
    "password":"pass123",
    "email":"hacker@evil.com",
    "role":"ADMIN",
    "isAdmin":true
  }'
# Before: Creates admin account ❌
```

After (Attack Blocked):
```bash
# Same request
# After: role and isAdmin fields are ignored
# Server creates USER account regardless ✅
```

---

##### d) Updated search() Method

**Before (VULNERABLE):**
```java
@GetMapping("/search")
public List<AppUser> search(@RequestParam String q) {
    return users.search(q);  // ❌ Exposes all user data
}
```

**After (SECURE):**
```java
@GetMapping("/search")
public ResponseEntity<?> search(@RequestParam String q, Authentication auth) {
    // Require authentication
    if (auth == null) {
        Map<String, String> error = new HashMap<>();
        error.put("error", "Authentication required");
        return ResponseEntity.status(401).body(error);
    }
    
    // Perform search and convert to DTOs
    List<AppUser> searchResults = users.search(q);
    
    // FIX(Task 4): Convert to DTOs to prevent exposing passwords, roles, admin flags
    List<UserResponseDTO> resultDTOs = DTOMapper.toUserDTOList(searchResults);
    
    return ResponseEntity.ok(resultDTOs);
}
```

**Security Improvements:**
- ✅ Authentication required (Task 2/3)
- ✅ Returns list of `UserResponseDTO` instead of entities
- ✅ Prevents exposing sensitive data in search results
- ✅ Note: Rate limiting still needed (Task 5)

---

##### e) Updated list() Method

**Before (VULNERABLE):**
```java
@GetMapping
public List<AppUser> list() {
    return users.findAll();  // ❌ Exposes all user data
}
```

**After (SECURE):**
```java
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
    
    // FIX(Task 4): Convert to DTOs to prevent exposing passwords, roles, admin flags
    List<UserResponseDTO> userDTOs = DTOMapper.toUserDTOList(allUsers);
    
    return ResponseEntity.ok(userDTOs);
}
```

**Security Improvements:**
- ✅ Authentication required
- ✅ Returns list of `UserResponseDTO`
- ✅ Prevents bulk password hash enumeration
- ✅ Hides internal authorization details

---

### Security Benefits

1. **Password Protection:**
   - BCrypt hashes never appear in API responses
   - Even authenticated users can't see their own password hashes
   - Reduces risk of offline brute force attacks

2. **Authorization Information Hiding:**
   - Roles and admin flags not exposed to clients
   - Clients can't enumerate admin accounts
   - Reduces reconnaissance information for attackers

3. **Database Schema Hiding:**
   - Foreign keys like `ownerUserId` not exposed
   - Internal relationships hidden from clients
   - Database structure remains opaque

4. **Mass Assignment Prevention:**
   - Input DTOs control what clients can set
   - Server has full control over sensitive fields
   - Prevents privilege escalation attacks

5. **Principle of Least Privilege:**
   - Clients only receive data they need
   - No internal implementation details leaked
   - Reduces attack surface

6. **Consistent Security:**
   - Centralized mapping logic in `DTOMapper`
   - All endpoints use same secure patterns
   - Easy to audit and maintain

### Testing the Fix

#### Test 1: Verify Password Not Exposed

**Test getting user profile:**
```powershell
# Login and get token
$response = curl -X POST http://localhost:8080/api/auth/login `
  -H "Content-Type: application/json" `
  -d '{"username":"alice","password":"alice123"}' | ConvertFrom-Json

# Get user profile
curl -X GET http://localhost:8080/api/users/1 `
  -H "Authorization: Bearer $($response.token)" | ConvertFrom-Json
```

**Expected Response:**
```json
{
  "id": 1,
  "username": "alice",
  "email": "alice@cydea.tech"
}
```

**Verify:**
- ✅ No `password` field
- ✅ No `role` field
- ✅ No `isAdmin` field

---

#### Test 2: Verify Account ownerUserId Not Exposed

**Test getting account list:**
```powershell
curl -X GET http://localhost:8080/api/accounts/mine `
  -H "Authorization: Bearer $($response.token)" | ConvertFrom-Json
```

**Expected Response:**
```json
[
  {
    "id": 1,
    "iban": "PK00-ALICE",
    "balance": 1000.0
  }
]
```

**Verify:**
- ✅ No `ownerUserId` field
- ✅ Only relevant account information

---

#### Test 3: Verify Mass Assignment Prevention

**Test creating user with admin privileges:**
```powershell
curl -X POST http://localhost:8080/api/users `
  -H "Content-Type: application/json" `
  -d '{
    "username":"attacker",
    "password":"password123",
    "email":"attacker@test.com",
    "role":"ADMIN",
    "isAdmin":true
  }' | ConvertFrom-Json
```

**Expected Response:**
```json
{
  "id": 3,
  "username": "attacker",
  "email": "attacker@test.com"
}
```

**Verify in Database:**
```sql
SELECT username, role, isAdmin FROM APP_USER WHERE username='attacker';
```

**Expected Result:**
```
username  | role | isAdmin
----------|------|--------
attacker  | USER | false
```

**Verification:**
- ✅ User created with USER role (not ADMIN)
- ✅ isAdmin is false (not true)
- ✅ Server ignored client-provided role and isAdmin
- ✅ Response doesn't include sensitive fields

---

#### Test 4: Verify User List Doesn't Expose Sensitive Data

**Test listing all users:**
```powershell
curl -X GET http://localhost:8080/api/users `
  -H "Authorization: Bearer $($response.token)" | ConvertFrom-Json
```

**Expected Response:**
```json
[
  {
    "id": 1,
    "username": "alice",
    "email": "alice@cydea.tech"
  },
  {
    "id": 2,
    "username": "bob",
    "email": "bob@cydea.tech"
  }
]
```

**Verify:**
- ✅ Multiple users returned
- ✅ No password hashes
- ✅ No role information
- ✅ No isAdmin flags
- ✅ Can't identify which users are admins

---

#### Test 5: Verify Search Results Safe

**Test searching users:**
```powershell
curl -X GET "http://localhost:8080/api/users/search?q=alice" `
  -H "Authorization: Bearer $($response.token)" | ConvertFrom-Json
```

**Expected Response:**
```json
[
  {
    "id": 1,
    "username": "alice",
    "email": "alice@cydea.tech"
  }
]
```

**Verify:**
- ✅ Search works
- ✅ No sensitive data in results
- ✅ Safe for user enumeration (rate limiting in Task 5 will further protect)

---

### Comparison: Before vs After

| Endpoint | Before (Vulnerable) | After (Fixed) |
|----------|-------------------|---------------|
| GET /api/users/{id} | Returns password hash, role, isAdmin | ✅ Returns only id, username, email |
| GET /api/users | Returns all user data with passwords | ✅ Returns only safe fields |
| GET /api/users/search | Returns passwords in results | ✅ Returns only safe fields |
| POST /api/users | Accepts role, isAdmin from client | ✅ Server controls role/isAdmin |
| POST /api/users (response) | Returns password hash back | ✅ Returns only safe fields |
| GET /api/accounts/mine | Returns ownerUserId | ✅ Returns only account data |

---

### Data Exposure Summary

**Sensitive Fields Removed from Responses:**

| Field | Entity | Why Sensitive | Fixed |
|-------|--------|---------------|-------|
| `password` | AppUser | BCrypt hash, enables offline attacks | ✅ |
| `role` | AppUser | Internal authorization detail | ✅ |
| `isAdmin` | AppUser | Internal privilege flag | ✅ |
| `ownerUserId` | Account | Internal foreign key | ✅ |

**Mass Assignment Fields Blocked:**

| Field | Why Dangerous | Fixed |
|-------|---------------|-------|
| `role` | Client could set "ADMIN" | ✅ |
| `isAdmin` | Client could set true | ✅ |

---

### Remaining Vulnerabilities (Future Tasks)

While Task 4 fixes data exposure and mass assignment, the following issues remain:

1. **No Rate Limiting** - Endpoints still vulnerable to brute force and enumeration (Task 5)
2. **Weak JWT** - Token configuration needs hardening (Task 7)
3. **Verbose Errors** - Error messages too detailed for production (Task 8)
4. **No Integration Tests** - Need tests to verify DTO behavior (Task 10)

These will be addressed in subsequent tasks.

---

### Files Created/Modified Summary

**New Files Created:**
1. ✅ `dto/UserResponseDTO.java` - Safe user data representation
2. ✅ `dto/AccountResponseDTO.java` - Safe account data representation
3. ✅ `dto/CreateUserRequest.java` - Secure user creation input
4. ✅ `dto/DTOMapper.java` - Centralized entity-to-DTO conversions

**Files Modified:**
1. ✅ `AccountController.java` - Uses DTOs for mine() endpoint
2. ✅ `UserController.java` - Uses DTOs for all endpoints, prevents mass assignment

**Package Structure:**
```
edu.nu.owaspapivulnlab/
├── dto/
│   ├── UserResponseDTO.java
│   ├── AccountResponseDTO.java
│   ├── CreateUserRequest.java
│   └── DTOMapper.java
└── web/
    ├── AccountController.java (updated)
    └── UserController.java (updated)
```

---

**Fix Completed:** ✅ Task 4 - Implement DTOs to Control Data Exposure  
**Date:** October 26, 2025  
**Security Level:** HIGH PRIORITY - API3 Excessive Data Exposure fixed, API6 Mass Assignment partially fixed

---

## Task 5: Add Rate Limiting

### Overview
Implemented rate limiting using Bucket4j to protect sensitive API endpoints from brute force attacks, API abuse, and denial of service. Different rate limits are applied based on endpoint sensitivity to balance security with usability.

### Vulnerability Description
**OWASP API Security Category:** API4:2023 - Unrestricted Resource Consumption

**Original Issue:**
- No rate limiting on any endpoints
- Attackers could make unlimited requests to sensitive endpoints
- Vulnerable to brute force attacks on `/api/auth/login`
- Vulnerable to spam attacks on `/api/auth/signup`
- Vulnerable to transaction abuse on `/api/accounts/transfer`
- Vulnerable to expensive query abuse on `/api/users/search`
- Could lead to denial of service by overwhelming the API
- No protection against automated attacks or bot traffic

**Example Attack Scenarios:**
1. **Brute Force Attack:** Attacker tries thousands of password combinations on login endpoint
2. **Spam Registration:** Automated bot creates hundreds of fake user accounts
3. **Transaction Abuse:** Attacker floods transfer endpoint to disrupt service or exploit race conditions
4. **Search Abuse:** Attacker runs expensive search queries repeatedly to degrade performance

### Changes Made

#### 1. pom.xml
**Location:** `pom.xml`

**Changes:**
- Added Bucket4j dependency for rate limiting functionality

**Code Added:**
```xml
<!-- TASK 5 FIX: Add Bucket4j for rate limiting to prevent API abuse -->
<dependency>
  <groupId>com.bucket4j</groupId>
  <artifactId>bucket4j-core</artifactId>
  <version>8.7.0</version>
</dependency>
```

**Impact:** Enables token bucket algorithm for flexible rate limiting with configurable refill rates.

---

#### 2. RateLimitingFilter.java (NEW FILE)
**Location:** `src/main/java/edu/nu/owaspapivulnlab/config/RateLimitingFilter.java`

**Purpose:** Servlet filter that intercepts all requests and enforces rate limits based on client IP address and endpoint.

**Key Components:**

**a) Token Bucket Storage:**
```java
// Store buckets per IP address to track rate limits independently
private final Map<String, Bucket> ipBuckets = new ConcurrentHashMap<>();
```
- Uses `ConcurrentHashMap` for thread-safe bucket storage
- Each IP address gets its own set of buckets
- Buckets are created on-demand and cached for performance

**b) Rate Limit Enforcement:**
```java
@Override
protected void doFilterInternal(HttpServletRequest request, 
                                HttpServletResponse response, 
                                FilterChain filterChain) 
        throws ServletException, IOException {
    
    // Get client IP address (consider X-Forwarded-For in production with proxy)
    String clientIp = getClientIp(request);
    String requestUri = request.getRequestURI();
    
    // Get or create bucket for this IP with appropriate rate limit
    Bucket bucket = resolveBucket(clientIp, requestUri);
    
    // Try to consume 1 token from the bucket
    if (bucket.tryConsume(1)) {
        // Token available - allow request to proceed
        filterChain.doFilter(request, response);
    } else {
        // No tokens available - rate limit exceeded
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType("application/json");
        response.getWriter().write(
            "{\"error\":\"Too many requests. Please try again later.\",\"status\":429}"
        );
    }
}
```

**c) Endpoint-Specific Rate Limits:**
```java
if (requestUri.startsWith("/api/auth/login")) {
    // CRITICAL: Login endpoint - strict rate limit to prevent brute force
    // 5 requests per minute = 1 request every 12 seconds
    limit = Bandwidth.builder()
            .capacity(5)
            .refillIntervally(5, Duration.ofMinutes(1))
            .build();
} else if (requestUri.startsWith("/api/auth/signup")) {
    // CRITICAL: Signup endpoint - prevent spam registration
    // 3 requests per minute = 1 request every 20 seconds
    limit = Bandwidth.builder()
            .capacity(3)
            .refillIntervally(3, Duration.ofMinutes(1))
            .build();
} else if (requestUri.startsWith("/api/accounts/transfer")) {
    // HIGH: Transfer endpoint - prevent transaction abuse
    // 10 requests per minute = 1 request every 6 seconds
    limit = Bandwidth.builder()
            .capacity(10)
            .refillIntervally(10, Duration.ofMinutes(1))
            .build();
} else if (requestUri.startsWith("/api/users/search")) {
    // MEDIUM: Search endpoint - prevent expensive query abuse
    // 20 requests per minute = 1 request every 3 seconds
    limit = Bandwidth.builder()
            .capacity(20)
            .refillIntervally(20, Duration.ofMinutes(1))
            .build();
} else {
    // LOW: General endpoints - standard protection
    // 100 requests per minute
    limit = Bandwidth.builder()
            .capacity(100)
            .refillIntervally(100, Duration.ofMinutes(1))
            .build();
}
```

**Rate Limit Strategy:**
- **Login (5/min):** Prevents brute force password guessing
- **Signup (3/min):** Prevents automated account creation spam
- **Transfer (10/min):** Prevents transaction flooding and race condition exploitation
- **Search (20/min):** Prevents expensive query abuse
- **General (100/min):** Protects all other endpoints from DoS

**d) IP Address Extraction:**
```java
private String getClientIp(HttpServletRequest request) {
    // Check for proxy headers first (X-Forwarded-For)
    String xForwardedFor = request.getHeader("X-Forwarded-For");
    if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
        // X-Forwarded-For can contain multiple IPs, take the first one
        return xForwardedFor.split(",")[0].trim();
    }
    
    // Fallback to remote address
    return request.getRemoteAddr();
}
```
- Handles proxy/load balancer scenarios by checking `X-Forwarded-For` header
- Falls back to `remoteAddr` for direct connections
- Ensures accurate IP-based rate limiting

**Impact:** 
- Prevents brute force attacks on authentication endpoints
- Mitigates denial of service attacks
- Protects expensive operations from abuse
- Maintains API availability for legitimate users

---

#### 3. SecurityConfig.java
**Location:** `src/main/java/edu/nu/owaspapivulnlab/config/SecurityConfig.java`

**Changes:**
- Injected `RateLimitingFilter` via constructor
- Registered rate limiting filter in the security filter chain
- Positioned rate limiting filter BEFORE JWT filter for early rejection

**Code Added:**

**Constructor Injection:**
```java
// TASK 5 FIX: Inject rate limiting filter
private final RateLimitingFilter rateLimitingFilter;

public SecurityConfig(RateLimitingFilter rateLimitingFilter) {
    this.rateLimitingFilter = rateLimitingFilter;
}
```

**Filter Registration:**
```java
// TASK 5 FIX: Add rate limiting filter BEFORE JWT filter
// This ensures rate limits are enforced even before JWT validation
// Prevents attackers from overwhelming the system with invalid tokens
http.addFilterBefore(rateLimitingFilter, 
    org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);

// FIX(Task 2): Add JWT filter before authentication filter
http.addFilterBefore(new JwtFilter(secret), 
    org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
```

**Impact:** 
- Rate limiting applied to ALL requests, including unauthenticated ones
- Attackers can't bypass rate limits by sending invalid tokens
- Protects JWT validation logic from being overwhelmed

---

### Before vs After Comparison

#### Before (Vulnerable):
```bash
# Attacker can make unlimited login attempts
for i in {1..1000}; do
  curl -X POST http://localhost:8080/api/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"alice","password":"guess'$i'"}'
done
# All 1000 requests succeed (even though passwords are wrong)
# Server processes all brute force attempts

# Attacker can spam signup endpoint
for i in {1..100}; do
  curl -X POST http://localhost:8080/api/auth/signup \
    -H 'Content-Type: application/json' \
    -d '{"username":"spam'$i'","password":"pass","email":"spam'$i'@test.com"}'
done
# All 100 accounts created successfully
```

#### After (Fixed):
```bash
# Attacker tries brute force on login
for i in {1..10}; do
  curl -X POST http://localhost:8080/api/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"alice","password":"guess'$i'"}'
  echo "Attempt $i"
done

# Response after 5 attempts:
# Attempt 1-5: {"error":"Invalid credentials"}  # Normal auth failure
# Attempt 6+: {"error":"Too many requests. Please try again later.","status":429}
# HTTP Status: 429 Too Many Requests

# Attacker tries spam signup
for i in {1..5}; do
  curl -X POST http://localhost:8080/api/auth/signup \
    -H 'Content-Type: application/json' \
    -d '{"username":"spam'$i'","password":"pass","email":"spam'$i'@test.com"}'
  echo "Attempt $i"
done

# Response after 3 attempts:
# Attempt 1-3: {"id":..., "username":"spam1"...}  # Success
# Attempt 4+: {"error":"Too many requests. Please try again later.","status":429}
# HTTP Status: 429 Too Many Requests
```

---

### Testing Procedures

#### Test 1: Login Rate Limit (5 requests/minute)
```bash
# Test brute force protection
for i in {1..7}; do
  curl -v -X POST http://localhost:8080/api/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"alice","password":"wrong'$i'"}'
  echo "\n--- Attempt $i completed ---\n"
done

# Expected Results:
# Attempts 1-5: HTTP 401 Unauthorized (invalid credentials)
# Attempts 6-7: HTTP 429 Too Many Requests (rate limit exceeded)
# Response: {"error":"Too many requests. Please try again later.","status":429}

# Wait 60 seconds and try again
sleep 60
curl -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}'
# Expected: HTTP 200 OK (tokens refilled, request allowed)
```

#### Test 2: Signup Rate Limit (3 requests/minute)
```bash
# Test spam registration protection
for i in {1..5}; do
  curl -v -X POST http://localhost:8080/api/auth/signup \
    -H 'Content-Type: application/json' \
    -d '{"username":"test'$i'","password":"pass123","email":"test'$i'@example.com"}'
  echo "\n--- Signup attempt $i completed ---\n"
done

# Expected Results:
# Attempts 1-3: HTTP 200 OK (accounts created)
# Attempts 4-5: HTTP 429 Too Many Requests (rate limit exceeded)
```

#### Test 3: Transfer Rate Limit (10 requests/minute)
```bash
# First, login as alice to get JWT
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}' | jq -r '.token')

# Test transfer rate limit
for i in {1..12}; do
  curl -v -X POST http://localhost:8080/api/accounts/transfer \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"fromId":1,"toId":2,"amount":1}'
  echo "\n--- Transfer attempt $i completed ---\n"
done

# Expected Results:
# Attempts 1-10: HTTP 200/400 (depending on balance, but request processed)
# Attempts 11-12: HTTP 429 Too Many Requests (rate limit exceeded)
```

#### Test 4: Search Rate Limit (20 requests/minute)
```bash
# Get admin token (bob)
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bob123"}' | jq -r '.token')

# Test search rate limit
for i in {1..25}; do
  curl -v http://localhost:8080/api/users/search?query=alice \
    -H "Authorization: Bearer $TOKEN"
  echo "\n--- Search attempt $i completed ---\n"
done

# Expected Results:
# Attempts 1-20: HTTP 200 OK (search results returned)
# Attempts 21-25: HTTP 429 Too Many Requests (rate limit exceeded)
```

#### Test 5: Different IPs Get Independent Buckets
```bash
# Simulate two different clients using different IPs
# (In production, X-Forwarded-For would differentiate them)

# Client 1: Make 5 login attempts
for i in {1..5}; do
  curl -X POST http://localhost:8080/api/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"alice","password":"wrong"}'
done

# Client 2: Should still have their own 5 attempts
# (In testing, this will share the same IP unless using proxy)
# In production with load balancers, different X-Forwarded-For headers
# would result in independent rate limits
```

---

### Security Benefits

#### 1. Brute Force Protection
- **Before:** Attackers could try unlimited password combinations
- **After:** Maximum 5 login attempts per minute per IP
- **Impact:** Makes password guessing attacks impractical

#### 2. Spam Prevention
- **Before:** Bots could create thousands of fake accounts
- **After:** Maximum 3 signups per minute per IP
- **Impact:** Significantly reduces automated account creation

#### 3. Transaction Abuse Prevention
- **Before:** Attackers could flood transfer endpoint
- **After:** Maximum 10 transfers per minute per IP
- **Impact:** Prevents transaction flooding and race condition exploitation

#### 4. Resource Protection
- **Before:** Expensive search queries could be run unlimited times
- **After:** Maximum 20 searches per minute per IP
- **Impact:** Protects database and server resources

#### 5. Denial of Service Mitigation
- **Before:** Single attacker could overwhelm the API
- **After:** All endpoints have rate limits
- **Impact:** Maintains API availability for legitimate users

#### 6. Early Detection
- **Before:** No visibility into abuse patterns
- **After:** 429 responses indicate potential attacks
- **Impact:** Enables monitoring and alerting on suspicious activity

---

### Token Bucket Algorithm Explained

Bucket4j implements the **Token Bucket Algorithm**:

1. **Bucket Capacity:** Maximum number of tokens (requests) that can be stored
2. **Refill Rate:** How quickly tokens are added back to the bucket
3. **Token Consumption:** Each request consumes 1 token
4. **Blocking:** If no tokens available, request is rejected with 429

**Example for Login (5 tokens, refill 5 per minute):**
```
Time    Tokens  Action
-----   ------  ------
00:00   5       Initial state
00:01   4       Login attempt 1 ✓
00:02   3       Login attempt 2 ✓
00:03   2       Login attempt 3 ✓
00:04   1       Login attempt 4 ✓
00:05   0       Login attempt 5 ✓
00:06   0       Login attempt 6 ✗ (429 Too Many Requests)
01:00   5       Tokens refilled (5 tokens added)
01:01   4       Login attempt 7 ✓ (allowed after refill)
```

**Advantages:**
- Allows bursts up to capacity
- Smooth refill over time
- Fair distribution of resources
- No need for persistent storage (in-memory)

---

### Production Considerations

#### 1. Distributed Systems
Current implementation uses in-memory storage (`ConcurrentHashMap`). For multi-instance deployments:
- Use Redis-backed Bucket4j: `bucket4j-redis`
- Share rate limit state across all API instances
- Ensures consistent rate limiting regardless of which instance handles the request

```xml
<!-- For production with multiple instances -->
<dependency>
  <groupId>com.bucket4j</groupId>
  <artifactId>bucket4j-redis</artifactId>
  <version>8.7.0</version>
</dependency>
```

#### 2. IP Address Extraction
Current implementation checks `X-Forwarded-For` header:
- Ensure load balancer/proxy sets this header correctly
- Consider validating against trusted proxy list
- Be aware of header spoofing in untrusted networks

#### 3. Rate Limit Tuning
Current limits are conservative. Consider:
- Monitoring actual usage patterns
- Adjusting limits based on legitimate user behavior
- Different limits for authenticated vs unauthenticated users
- Premium users might get higher limits

#### 4. Response Headers
Consider adding rate limit headers for better client experience:
```java
response.setHeader("X-RateLimit-Limit", "5");
response.setHeader("X-RateLimit-Remaining", "0");
response.setHeader("X-RateLimit-Reset", "60"); // seconds until reset
```

#### 5. Monitoring & Alerting
- Log 429 responses for security monitoring
- Alert on sustained high rate of 429s (potential attack)
- Track which endpoints are most frequently rate-limited
- Monitor bucket memory usage

---

### Related OWASP Fixes

This fix complements other security measures:
- **Task 1 (BCrypt):** Rate limiting makes brute force even less effective
- **Task 2 (SecurityFilterChain):** Rate limiting applied before authentication
- **Task 3 (Ownership):** Rate limiting protects ownership checks from DoS
- **Task 4 (DTOs):** Rate limiting prevents mass data extraction attempts

---

### Files Modified

1. ✅ `pom.xml` - Added Bucket4j dependency
2. ✅ `RateLimitingFilter.java` (NEW) - Implemented rate limiting filter with endpoint-specific limits
3. ✅ `SecurityConfig.java` - Injected and registered rate limiting filter in security chain

---

**Fix Completed:** ✅ Task 5 - Add Rate Limiting  
**Date:** October 26, 2025  
**Security Level:** CRITICAL - API4 Unrestricted Resource Consumption fixed

---

## Task 6: Prevent Mass Assignment

### Overview
Completed the mass assignment prevention started in Task 4 by ensuring all user creation endpoints properly use explicit DTOs and server-side validation. Reviewed and fixed collaborator changes to ensure passwords are hashed and privilege fields are server-controlled.

### Vulnerability Description
**OWASP API Security Category:** API6:2023 - Unrestricted Access to Sensitive Business Flows (Mass Assignment)

**Original Issue:**
- API endpoints that accept JSON objects can automatically bind all fields from request to entity
- Attackers could send additional fields like `{"username":"hacker","password":"pass","role":"ADMIN","isAdmin":true}`
- Without explicit DTOs, Spring Boot would bind these dangerous fields directly to the entity
- This allows privilege escalation attacks where regular users can make themselves admins

**Attack Scenario:**
```bash
# Attacker creates account with admin privileges
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "username": "hacker",
    "password": "password123",
    "email": "hacker@evil.com",
    "role": "ADMIN",
    "isAdmin": true
  }'

# Without mass assignment protection: User created as ADMIN
# With mass assignment protection: role and isAdmin ignored, user created as USER
```

### Changes Made

#### 1. AppUser.java
**Location:** `src/main/java/edu/nu/owaspapivulnlab/model/AppUser.java`

**Changes:**
- Updated comments to clarify that role and isAdmin fields are server-controlled
- Documented that these fields are NOT exposed in CreateUserRequest DTO
- Explained the vulnerability fix clearly

**Code Updated:**
```java
// FIX(Task 6): Mass Assignment Protection
// These fields (role, isAdmin) are NOT exposed in CreateUserRequest DTO
// Server-side code explicitly sets these values to prevent privilege escalation
// VULNERABILITY FIXED: Clients can no longer send {"role":"ADMIN","isAdmin":true} in POST requests
private String role;   // e.g., "USER" or "ADMIN" - server controlled
private boolean isAdmin; // Server controlled - cannot be set via API
```

**Impact:** Clear documentation that these fields are protected from client manipulation.

---

#### 2. UserController.java (Reviewed and Fixed Collaborator Changes)
**Location:** `src/main/java/edu/nu/owaspapivulnlab/web/UserController.java`

**Issues Found in Collaborator's Changes:**
1. ❌ Used Java `record` syntax which isn't compatible with Java 8 target (causes compilation errors)
2. ❌ Created duplicate DTO (`UserRegistrationDTO`) when `CreateUserRequest` already exists
3. ❌ Injected `passwordEncoder` but didn't use it - password not hashed!
4. ❌ Returned raw `AppUser` entity instead of `UserResponseDTO`
5. ❌ Missing authentication and authorization checks

**Fixed Implementation:**
```java
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
    AppUser currentUser = users.findByUsername(auth.getName())
            .orElseThrow(() -> new RuntimeException("User not found"));
    
    if (!currentUser.isAdmin()) {
        Map<String, String> error = new HashMap<>();
        error.put("error", "Access denied - admin privileges required");
        return ResponseEntity.status(403).body(error);
    }
    
    // Check if username already exists
    if (users.findByUsername(body.getUsername()).isPresent()) {
        Map<String, String> error = new HashMap<>();
        error.put("error", "Username already exists");
        return ResponseEntity.status(400).body(error);
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
```

**What Was Fixed:**
1. ✅ Removed Java `record` and used existing `CreateUserRequest` DTO
2. ✅ Actually used `passwordEncoder` to hash passwords with BCrypt
3. ✅ Added authentication check (must be logged in)
4. ✅ Added authorization check (only admins can create users)
5. ✅ Added username uniqueness check
6. ✅ Explicitly set `role = "USER"` and `isAdmin = false` (server-controlled)
7. ✅ Returned `UserResponseDTO` instead of raw entity
8. ✅ Added proper error handling with HTTP status codes

**Impact:**
- Passwords are now properly hashed before storage
- role and isAdmin cannot be set by client - always server-controlled
- Only admins can create users (prevents unauthorized account creation)
- Sensitive data not exposed in response (uses DTO)
- Proper validation and error handling

---

### CreateUserRequest DTO (Already Created in Task 4)
**Location:** `src/main/java/edu/nu/owaspapivulnlab/dto/CreateUserRequest.java`

This DTO was already created in Task 4 and is the proper way to prevent mass assignment:

```java
@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateUserRequest {
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;
    
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    private String password;
    
    @Email(message = "Valid email is required")
    @NotBlank(message = "Email is required")
    private String email;
    
    // FIX(Task 6): Dangerous fields intentionally excluded:
    // - role: Server assigns default "USER" role
    // - isAdmin: Server controls admin privileges, not client
    // This prevents privilege escalation attacks via mass assignment
}
```

**Key Security Features:**
- Only accepts username, password, and email
- Excludes role and isAdmin fields completely
- Includes validation annotations for input sanitization
- Server code explicitly sets role="USER" and isAdmin=false

---

### Before vs After Comparison

#### Before (Vulnerable):
```java
// Old vulnerable code (hypothetical)
@PostMapping
public AppUser create(@RequestBody AppUser user) {
    return users.save(user);  // Binds ALL fields from JSON!
}

// Attack request:
POST /api/users
{
  "username": "hacker",
  "password": "pass",
  "email": "hack@evil.com",
  "role": "ADMIN",        // ❌ Bound to entity!
  "isAdmin": true          // ❌ Bound to entity!
}

// Result: User created with ADMIN role and isAdmin=true
```

#### After (Fixed):
```java
// Fixed code with explicit DTO
@PostMapping
public ResponseEntity<?> create(@Valid @RequestBody CreateUserRequest body, Authentication auth) {
    // Authorization check
    if (!currentUser.isAdmin()) {
        return ResponseEntity.status(403).body(error);
    }
    
    // Explicit field mapping with server-controlled values
    AppUser user = AppUser.builder()
        .username(body.getUsername())           // From DTO
        .password(passwordEncoder.encode(...))  // Hashed
        .email(body.getEmail())                 // From DTO
        .role("USER")                           // Server controlled!
        .isAdmin(false)                         // Server controlled!
        .build();
    
    return ResponseEntity.ok(DTOMapper.toUserDTO(users.save(user)));
}

// Attack attempt:
POST /api/users
{
  "username": "hacker",
  "password": "pass",
  "email": "hack@evil.com",
  "role": "ADMIN",        // ✅ Ignored (not in DTO)
  "isAdmin": true          // ✅ Ignored (not in DTO)
}

// Result: User created with role="USER" and isAdmin=false
// Attack fields ignored because CreateUserRequest doesn't have those fields
```

---

### Testing Procedures

#### Test 1: Verify Mass Assignment is Blocked
```bash
# Login as admin (bob)
TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"bob","password":"bob123"}' | jq -r '.token')

# Try to create user with admin privileges
curl -v -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "attacker",
    "password": "password123",
    "email": "attacker@evil.com",
    "role": "ADMIN",
    "isAdmin": true
  }'

# Expected Response:
# HTTP 200 OK
# {
#   "id": 3,
#   "username": "attacker",
#   "email": "attacker@evil.com"
# }
# Note: role and isAdmin NOT in response (DTO filters them)

# Verify in database (H2 Console):
SELECT * FROM APP_USER WHERE username = 'attacker';
# Expected: role='USER', is_admin=false (server-controlled)
```

#### Test 2: Verify Password is Hashed
```bash
# Create a new user
curl -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "testuser",
    "password": "mypassword123",
    "email": "test@example.com"
  }'

# Check database:
SELECT username, password FROM APP_USER WHERE username = 'testuser';
# Expected: password starts with $2a$ or $2b$ (BCrypt hash)
# NOT: password = 'mypassword123' (plaintext)
```

#### Test 3: Verify Non-Admins Cannot Create Users
```bash
# Login as regular user (alice)
ALICE_TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}' | jq -r '.token')

# Try to create user as non-admin
curl -v -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer $ALICE_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "newuser",
    "password": "password123",
    "email": "new@example.com"
  }'

# Expected Response:
# HTTP 403 Forbidden
# {"error":"Access denied - admin privileges required"}
```

#### Test 4: Verify Validation Works
```bash
# Try to create user with invalid email
curl -v -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "baduser",
    "password": "pass",
    "email": "not-an-email"
  }'

# Expected: HTTP 400 Bad Request
# Validation error for @Email annotation

# Try to create user with short password
curl -v -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "baduser",
    "password": "short",
    "email": "test@example.com"
  }'

# Expected: HTTP 400 Bad Request
# Validation error: "Password must be at least 8 characters"
```

#### Test 5: Verify Duplicate Username Rejected
```bash
# Try to create user with existing username
curl -v -X POST http://localhost:8080/api/users \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "username": "alice",
    "password": "password123",
    "email": "duplicate@example.com"
  }'

# Expected Response:
# HTTP 400 Bad Request
# {"error":"Username already exists"}
```

---

### Security Benefits

#### 1. Privilege Escalation Prevention
- **Before:** Attackers could set role="ADMIN" in request
- **After:** Server explicitly controls role assignment
- **Impact:** Prevents unauthorized admin access

#### 2. Password Security
- **Before:** Collaborator's code didn't hash passwords
- **After:** All passwords hashed with BCrypt
- **Impact:** Passwords protected even if database compromised

#### 3. Data Exposure Prevention
- **Before:** Raw entity returned (exposes role, isAdmin, password hash)
- **After:** DTO returned (only safe fields exposed)
- **Impact:** Sensitive metadata not leaked to clients

#### 4. Authorization Control
- **Before:** Anyone could create users
- **After:** Only admins can create users
- **Impact:** Prevents unauthorized account creation

#### 5. Input Validation
- **Before:** No validation on input fields
- **After:** @Valid with comprehensive constraints
- **Impact:** Rejects malformed data before processing

#### 6. Duplicate Prevention
- **Before:** No uniqueness check
- **After:** Username uniqueness enforced
- **Impact:** Prevents database constraint violations

---

### Mass Assignment Defense Layers

This implementation uses **defense in depth** with multiple protection layers:

1. **DTO Layer:** CreateUserRequest excludes dangerous fields
2. **Server-Side Assignment:** Explicit .role("USER") and .isAdmin(false)
3. **Authorization:** Only admins can create users
4. **Validation:** Input sanitization with Bean Validation
5. **Response Filtering:** UserResponseDTO hides sensitive data
6. **Password Hashing:** BCrypt encoding before storage

**Even if one layer fails, others provide backup protection.**

---

### Code Review Summary

**Collaborator's Changes Reviewed:**
- ✅ Concept was correct (use explicit DTO, set role/isAdmin manually)
- ❌ Implementation had critical issues:
  - Java `record` syntax incompatible with Java 8 target
  - Password not hashed (security vulnerability)
  - Missing authentication/authorization checks
  - No validation or error handling
  - Returned raw entity instead of DTO

**Fixed Implementation:**
- ✅ Uses existing CreateUserRequest DTO (no duplicate)
- ✅ Properly hashes passwords with BCrypt
- ✅ Enforces authentication and admin authorization
- ✅ Validates input with Bean Validation
- ✅ Returns safe DTO response
- ✅ Handles errors with proper HTTP status codes
- ✅ Checks username uniqueness
- ✅ Fully documented with comments

---

### Relationship to Other Tasks

Task 6 completes the mass assignment prevention started in Task 4:

- **Task 4:** Created DTOs for output (UserResponseDTO, AccountResponseDTO)
- **Task 4:** Created CreateUserRequest for input
- **Task 6:** Ensured CreateUserRequest is properly used in create() endpoint
- **Task 6:** Fixed collaborator's incomplete implementation
- **Task 6:** Added all missing security controls

Together, Tasks 4 and 6 provide comprehensive protection against:
- API3: Excessive Data Exposure (Task 4 output DTOs)
- API6: Mass Assignment (Task 4 + Task 6 input DTOs with server-side control)

---

### Production Considerations

#### 1. Audit Logging
Add logging for privilege-related actions:
```java
log.info("User created: username={}, role={}, createdBy={}", 
    user.getUsername(), user.getRole(), currentUser.getUsername());
```

#### 2. Role Management
For production, consider:
- Role-based access control (RBAC) with proper role hierarchy
- Separate endpoint for admin promotion (with strict controls)
- Audit trail for all role changes

#### 3. Account Approval Workflow
Consider requiring admin approval for new accounts:
```java
.role("USER")
.isAdmin(false)
.approved(false)  // Requires admin approval
```

#### 4. Email Verification
Add email verification before account activation:
```java
.emailVerified(false)
.verificationToken(UUID.randomUUID().toString())
```

---

### Files Modified

1. ✅ `AppUser.java` - Updated comments documenting mass assignment protection
2. ✅ `UserController.java` - Fixed create() method to properly prevent mass assignment
3. ✅ `CreateUserRequest.java` - Already exists from Task 4 (no changes needed)
4. ✅ `fixes_made.md` - Comprehensive Task 6 documentation

---

**Fix Completed:** ✅ Task 6 - Prevent Mass Assignment  
**Date:** October 26, 2025  
**Security Level:** CRITICAL - API6 Mass Assignment vulnerability FIXED  
**Collaborator Review:** Issues identified and corrected

