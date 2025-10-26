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
 * TASK 10: Integration Tests - Input Validation
 * Tests for Task 9 (Input Validation)
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test") // TASK 10: Use test profile to avoid rate limiting issues
@DisplayName("Input Validation Tests")
class InputValidationIntegrationTest {

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
    // TASK 9: Transfer Amount Validation Tests
    // ========================================

    @Test
    @DisplayName("TASK 9 FIX: Negative transfer amount is rejected")
    void testNegativeTransferAmountRejected() throws Exception {
        String token = login("alice", "alice123");
        String negativeTransferPayload = "{\"amount\":-100.0}";
        
        mvc.perform(post("/api/accounts/1/transfer")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(negativeTransferPayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"))
                .andExpect(jsonPath("$.message").value(containsString("must be at least")));
    }

    @Test
    @DisplayName("TASK 9 FIX: Zero transfer amount is rejected")
    void testZeroTransferAmountRejected() throws Exception {
        String token = login("alice", "alice123");
        String zeroTransferPayload = "{\"amount\":0.0}";
        
        mvc.perform(post("/api/accounts/1/transfer")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(zeroTransferPayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"))
                .andExpect(jsonPath("$.message").value(containsString("must be at least")));
    }

    @Test
    @DisplayName("TASK 9 FIX: Excessive transfer amount is rejected")
    void testExcessiveTransferAmountRejected() throws Exception {
        String token = login("alice", "alice123");
        String excessiveTransferPayload = "{\"amount\":2000000.0}";
        
        mvc.perform(post("/api/accounts/1/transfer")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(excessiveTransferPayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"))
                .andExpect(jsonPath("$.message").value(containsString("cannot exceed")));
    }

    @Test
    @DisplayName("TASK 9 FIX: Null transfer amount is rejected")
    void testNullTransferAmountRejected() throws Exception {
        String token = login("alice", "alice123");
        String nullTransferPayload = "{}";
        
        mvc.perform(post("/api/accounts/1/transfer")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(nullTransferPayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"));
    }

    @Test
    @DisplayName("TASK 9 FIX: Valid transfer amount succeeds")
    void testValidTransferAmountSucceeds() throws Exception {
        String token = login("alice", "alice123");
        String validTransferPayload = "{\"amount\":50.0}";
        
        mvc.perform(post("/api/accounts/1/transfer")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(validTransferPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ok"))
                .andExpect(jsonPath("$.transferred").value(50.0));
    }

    @Test
    @DisplayName("TASK 9 FIX: Transfer with insufficient balance is rejected")
    void testTransferWithInsufficientBalanceRejected() throws Exception {
        String token = login("alice", "alice123");
        // Try to transfer more than account balance
        String insufficientBalancePayload = "{\"amount\":999999.0}";
        
        mvc.perform(post("/api/accounts/1/transfer")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(insufficientBalancePayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"))
                .andExpect(jsonPath("$.message").value(containsString("Insufficient balance")));
    }

    // ========================================
    // TASK 9: Login Validation Tests
    // ========================================

    @Test
    @DisplayName("TASK 9 FIX: Login with empty username is rejected")
    void testLoginWithEmptyUsernameRejected() throws Exception {
        String emptyUsernamePayload = "{\"username\":\"\",\"password\":\"password123\"}";
        
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(emptyUsernamePayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"))
                .andExpect(jsonPath("$.message").value(containsString("Username is required")));
    }

    @Test
    @DisplayName("TASK 9 FIX: Login with empty password is rejected")
    void testLoginWithEmptyPasswordRejected() throws Exception {
        String emptyPasswordPayload = "{\"username\":\"alice\",\"password\":\"\"}";
        
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(emptyPasswordPayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"))
                .andExpect(jsonPath("$.message").value(containsString("Password is required")));
    }

    @Test
    @DisplayName("TASK 9 FIX: Login with both empty credentials is rejected")
    void testLoginWithBothEmptyCredentialsRejected() throws Exception {
        String emptyCredsPayload = "{\"username\":\"\",\"password\":\"\"}";
        
        mvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(emptyCredsPayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"));
    }

    // ========================================
    // TASK 9: Signup Validation Tests
    // ========================================

    @Test
    @DisplayName("TASK 9 FIX: Signup with short username is rejected")
    void testSignupWithShortUsernameRejected() throws Exception {
        String shortUsernamePayload = "{\"username\":\"ab\",\"password\":\"password123\",\"email\":\"test@test.com\"}";
        
        mvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(shortUsernamePayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"))
                .andExpect(jsonPath("$.message").value(containsString("between 3 and 50")));
    }

    @Test
    @DisplayName("TASK 9 FIX: Signup with short password is rejected")
    void testSignupWithShortPasswordRejected() throws Exception {
        String shortPasswordPayload = "{\"username\":\"testuser\",\"password\":\"short\",\"email\":\"test@test.com\"}";
        
        mvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(shortPasswordPayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"))
                .andExpect(jsonPath("$.message").value(containsString("8 and 128")));
    }

    @Test
    @DisplayName("TASK 9 FIX: Signup with invalid email is rejected")
    void testSignupWithInvalidEmailRejected() throws Exception {
        String invalidEmailPayload = "{\"username\":\"testuser\",\"password\":\"password123\",\"email\":\"not-an-email\"}";
        
        mvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidEmailPayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"))
                .andExpect(jsonPath("$.message").value(containsString("email")));
    }

    @Test
    @DisplayName("TASK 9 FIX: Signup with XSS in username is rejected")
    void testSignupWithXSSInUsernameRejected() throws Exception {
        String xssPayload = "{\"username\":\"<script>alert(1)</script>\",\"password\":\"password123\",\"email\":\"test@test.com\"}";
        
        mvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(xssPayload))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value(containsString("invalid")));
    }

    @Test
    @DisplayName("TASK 9 FIX: Signup with special characters in username is rejected")
    void testSignupWithSpecialCharactersRejected() throws Exception {
        String specialCharsPayload = "{\"username\":\"test<>user\",\"password\":\"password123\",\"email\":\"test@test.com\"}";
        
        mvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(specialCharsPayload))
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("TASK 9 FIX: Valid signup succeeds")
    void testValidSignupSucceeds() throws Exception {
        String validPayload = "{\"username\":\"validuser123\",\"password\":\"securepass123\",\"email\":\"valid@test.com\"}";
        
        mvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(validPayload))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("user created successfully"));
    }

    // ========================================
    // TASK 9: Search Query Validation Tests
    // ========================================

    @Test
    @DisplayName("TASK 9 FIX: Search with empty query is rejected")
    void testSearchWithEmptyQueryRejected() throws Exception {
        String token = login("alice", "alice123");
        
        mvc.perform(get("/api/users/search")
                .param("q", "")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"))
                .andExpect(jsonPath("$.message").value(containsString("cannot be empty")));
    }

    @Test
    @DisplayName("TASK 9 FIX: Search with SQL injection pattern is rejected")
    void testSearchWithSQLInjectionRejected() throws Exception {
        String token = login("alice", "alice123");
        
        mvc.perform(get("/api/users/search")
                .param("q", "'; DROP TABLE app_user; --")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"))
                .andExpect(jsonPath("$.message").value(containsString("invalid characters")));
    }

    @Test
    @DisplayName("TASK 9 FIX: Search with excessively long query is rejected")
    void testSearchWithLongQueryRejected() throws Exception {
        String token = login("alice", "alice123");
        String longQuery = "a".repeat(200);
        
        mvc.perform(get("/api/users/search")
                .param("q", longQuery)
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"))
                .andExpect(jsonPath("$.message").value(containsString("too long")));
    }

    @Test
    @DisplayName("TASK 9 FIX: Valid search query succeeds")
    void testValidSearchQuerySucceeds() throws Exception {
        String token = login("alice", "alice123");
        
        mvc.perform(get("/api/users/search")
                .param("q", "alice")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    // ========================================
    // TASK 9: User Creation Validation Tests (Admin)
    // ========================================

    @Test
    @DisplayName("TASK 9 FIX: Create user with invalid username pattern is rejected")
    void testCreateUserWithInvalidUsernamePatternRejected() throws Exception {
        String token = login("bob", "bob123");
        String invalidPattern = "{\"username\":\"user@#$\",\"password\":\"password123\",\"email\":\"test@test.com\"}";
        
        mvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(invalidPattern))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("Validation Error"))
                .andExpect(jsonPath("$.message").value(containsString("letters, numbers")));
    }

    @Test
    @DisplayName("TASK 9 FIX: Create user with valid data succeeds")
    void testCreateUserWithValidDataSucceeds() throws Exception {
        String token = login("bob", "bob123");
        String validPayload = "{\"username\":\"validuser_123\",\"password\":\"password123\",\"email\":\"valid@test.com\"}";
        
        mvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(validPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("validuser_123"));
    }

    // ========================================
    // TASK 9: Decimal Precision Tests
    // ========================================

    @Test
    @DisplayName("TASK 9 FIX: Transfer with valid decimal precision succeeds")
    void testTransferWithValidDecimalPrecision() throws Exception {
        String token = login("alice", "alice123");
        String validDecimalPayload = "{\"amount\":123.45}";
        
        mvc.perform(post("/api/accounts/1/transfer")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(validDecimalPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.transferred").value(123.45));
    }

    @Test
    @DisplayName("TASK 9 FIX: Transfer minimum valid amount succeeds")
    void testTransferMinimumValidAmount() throws Exception {
        String token = login("alice", "alice123");
        String minAmountPayload = "{\"amount\":0.01}";
        
        mvc.perform(post("/api/accounts/1/transfer")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(minAmountPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.transferred").value(0.01));
    }

    @Test
    @DisplayName("TASK 9 FIX: Transfer maximum valid amount succeeds")
    void testTransferMaximumValidAmount() throws Exception {
        String token = login("alice", "alice123");
        // First check if balance is sufficient, otherwise this will fail with insufficient balance
        String maxAmountPayload = "{\"amount\":1000.00}";
        
        mvc.perform(post("/api/accounts/1/transfer")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(maxAmountPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.transferred").value(1000.00));
    }
}
