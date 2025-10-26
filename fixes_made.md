# Security Fixes Documentation

## Table of Contents
1. [Task 1: Replace Plaintext Passwords with BCrypt](#task-1-replace-plaintext-passwords-with-bcrypt)
2. [Task 2: Tighten SecurityFilterChain](#task-2-tighten-securityfilterchain)

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
