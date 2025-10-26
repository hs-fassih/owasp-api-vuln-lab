package edu.nu.owaspapivulnlab;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * TASK 10: Integration Tests - Authentication & Authorization
 * Tests for Task 1 (BCrypt), Task 2 (SecurityFilterChain), Task 3 (Ownership), Task 5 (BFLA)
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test") // TASK 10: Use test profile to avoid rate limiting issues
@DisplayName("Authentication and Authorization Tests")
class AuthenticationAuthorizationIntegrationTest {

    @Autowired
    private MockMvc mvc;

    @Autowired
    private ObjectMapper objectMapper;

    /**
     * TASK 10 TEST: Helper method to login and extract JWT token
     */
    private String login(String username, String password) throws Exception {
        String loginPayload = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
        
        String response = mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginPayload))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        
        return objectMapper.readTree(response).get("token").asText();
    }

    // ========================================
    // TASK 1: BCrypt Password Hashing Tests
    // ========================================

    @Test
    @DisplayName("TASK 1 FIX: Login with valid BCrypt hashed password succeeds")
    void testLoginWithValidBCryptPassword() throws Exception {
        // Alice's password is hashed with BCrypt in DataSeeder
        String loginPayload = "{\"username\":\"alice\",\"password\":\"alice123\"}";
        
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty());
    }

    @Test
    @DisplayName("TASK 1 FIX: Login with invalid password fails")
    void testLoginWithInvalidPassword() throws Exception {
        String loginPayload = "{\"username\":\"alice\",\"password\":\"wrongpassword\"}";
        
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginPayload))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("invalid credentials"));
    }

    @Test
    @DisplayName("TASK 1 FIX: Signup creates user with BCrypt hashed password")
    void testSignupWithBCryptHashing() throws Exception {
        String signupPayload = "{\"username\":\"newuser123\",\"password\":\"securepass123\",\"email\":\"new@test.com\"}";
        
        mvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(signupPayload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("user created successfully"));
        
        // Verify can login with the created credentials
        String loginPayload = "{\"username\":\"newuser123\",\"password\":\"securepass123\"}";
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty());
    }

    // ========================================
    // TASK 2: SecurityFilterChain Tests
    // ========================================

    @Test
    @DisplayName("TASK 2 FIX: Protected endpoints require authentication")
    void testProtectedEndpointsRequireAuth() throws Exception {
        // /api/users requires authentication
        mvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized());
        
        // /api/accounts/mine requires authentication
        mvc.perform(get("/api/accounts/mine"))
                .andExpect(status().isUnauthorized());
        
        // /api/users/search requires authentication
        mvc.perform(get("/api/users/search").param("q", "alice"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("TASK 2 FIX: Public endpoints do not require authentication")
    void testPublicEndpointsAccessible() throws Exception {
        // Login and signup should be accessible without token
        String loginPayload = "{\"username\":\"alice\",\"password\":\"alice123\"}";
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginPayload))
                .andExpect(status().isOk());
        
        String signupPayload = "{\"username\":\"publictest\",\"password\":\"password123\",\"email\":\"public@test.com\"}";
        mvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(signupPayload))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("TASK 2 FIX: Authenticated requests with valid JWT succeed")
    void testAuthenticatedRequestsSucceed() throws Exception {
        String token = login("alice", "alice123");
        
        mvc.perform(get("/api/accounts/mine")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
    }

    // ========================================
    // TASK 3: Ownership Verification Tests (BOLA Prevention)
    // ========================================

    @Test
    @DisplayName("TASK 3 FIX: User can only view their own profile")
    void testUserCanOnlyViewOwnProfile() throws Exception {
        String aliceToken = login("alice", "alice123");
        
        // Alice can view her own profile (user ID 1)
        mvc.perform(get("/api/users/1")
                .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"));
        
        // Alice cannot view Bob's profile (user ID 2)
        mvc.perform(get("/api/users/2")
                .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Access Denied"));
    }

    @Test
    @DisplayName("TASK 3 FIX: User can only access their own account balance")
    void testUserCanOnlyAccessOwnAccountBalance() throws Exception {
        String aliceToken = login("alice", "alice123");
        
        // Alice can view her own account balance (account ID 1)
        mvc.perform(get("/api/accounts/1/balance")
                .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.balance").exists());
        
        // Alice cannot view Bob's account balance (account ID 2)
        mvc.perform(get("/api/accounts/2/balance")
                .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Access Denied"));
    }

    @Test
    @DisplayName("TASK 3 FIX: User can only transfer from their own accounts")
    void testUserCanOnlyTransferFromOwnAccounts() throws Exception {
        String aliceToken = login("alice", "alice123");
        String transferPayload = "{\"amount\":10.0}";
        
        // Alice can transfer from her own account (account ID 1)
        mvc.perform(post("/api/accounts/1/transfer")
                .header("Authorization", "Bearer " + aliceToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(transferPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"));
        
        // Alice cannot transfer from Bob's account (account ID 2)
        mvc.perform(post("/api/accounts/2/transfer")
                .header("Authorization", "Bearer " + aliceToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(transferPayload))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Access Denied"));
    }

    // ========================================
    // TASK 5: Broken Function Level Authorization (BFLA) Tests
    // ========================================

    @Test
    @DisplayName("TASK 5 FIX: Non-admin cannot create users")
    void testNonAdminCannotCreateUsers() throws Exception {
        String aliceToken = login("alice", "alice123");
        String createUserPayload = "{\"username\":\"hackuser\",\"password\":\"password123\",\"email\":\"hack@test.com\"}";
        
        mvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + aliceToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createUserPayload))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Access Denied"));
    }

    @Test
    @DisplayName("TASK 5 FIX: Admin can create users")
    void testAdminCanCreateUsers() throws Exception {
        String bobToken = login("bob", "bob123");
        String createUserPayload = "{\"username\":\"adminuser1\",\"password\":\"password123\",\"email\":\"admin@test.com\"}";
        
        mvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + bobToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createUserPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("adminuser1"));
    }

    @Test
    @DisplayName("TASK 5 FIX: Non-admin cannot delete users")
    void testNonAdminCannotDeleteUsers() throws Exception {
        String aliceToken = login("alice", "alice123");
        
        mvc.perform(delete("/api/users/2")
                .header("Authorization", "Bearer " + aliceToken))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Access Denied"));
    }

    @Test
    @DisplayName("TASK 5 FIX: Admin can delete users (but not themselves)")
    void testAdminCanDeleteOtherUsers() throws Exception {
        String bobToken = login("bob", "bob123");
        
        // Bob cannot delete himself (user ID 2)
        mvc.perform(delete("/api/users/2")
                .header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"));
    }

    @Test
    @DisplayName("TASK 3 FIX: Admin can view any user profile")
    void testAdminCanViewAnyProfile() throws Exception {
        String bobToken = login("bob", "bob123");
        
        // Bob (admin) can view Alice's profile
        mvc.perform(get("/api/users/1")
                .header("Authorization", "Bearer " + bobToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("alice"));
    }
}
