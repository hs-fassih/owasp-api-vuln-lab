package edu.nu.owaspapivulnlab;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * TASK 10: Integration Tests - Data Exposure & Mass Assignment
 * Tests for Task 4 (DTOs), Task 6 (Mass Assignment Prevention)
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test") // TASK 10: Use test profile to avoid rate limiting issues
@DisplayName("Data Exposure and Mass Assignment Tests")
class DataExposureMassAssignmentIntegrationTest {

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
    // TASK 4: DTO Implementation Tests (Excessive Data Exposure Prevention)
    // ========================================

    @Test
    @DisplayName("TASK 4 FIX: User endpoint returns DTO without sensitive data")
    void testUserEndpointReturnsDTOWithoutSensitiveData() throws Exception {
        String token = login("alice", "alice123");
        
        MvcResult result = mvc.perform(get("/api/users/1")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        
        String responseBody = result.getResponse().getContentAsString();
        JsonNode userJson = objectMapper.readTree(responseBody);
        
        // TASK 4 FIX: Password should NOT be exposed
        assertFalse(userJson.has("password"), 
                "Password field should not be exposed in user response");
        
        // TASK 4 FIX: Role should NOT be exposed
        assertFalse(userJson.has("role"), 
                "Role field should not be exposed in user response");
        
        // TASK 4 FIX: isAdmin should NOT be exposed
        assertFalse(userJson.has("isAdmin"), 
                "isAdmin field should not be exposed in user response");
        
        // Safe fields should be present
        assertTrue(userJson.has("id"), "ID should be present");
        assertTrue(userJson.has("username"), "Username should be present");
        assertTrue(userJson.has("email"), "Email should be present");
    }

    @Test
    @DisplayName("TASK 4 FIX: List users endpoint returns DTOs without sensitive data")
    void testListUsersReturnsDTOs() throws Exception {
        String token = login("alice", "alice123");
        
        MvcResult result = mvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        
        String responseBody = result.getResponse().getContentAsString();
        JsonNode usersArray = objectMapper.readTree(responseBody);
        
        assertTrue(usersArray.isArray(), "Response should be an array");
        assertTrue(usersArray.size() > 0, "Should return at least one user");
        
        // Check first user in list
        JsonNode firstUser = usersArray.get(0);
        assertFalse(firstUser.has("password"), 
                "Password should not be exposed in user list");
        assertFalse(firstUser.has("role"), 
                "Role should not be exposed in user list");
        assertFalse(firstUser.has("isAdmin"), 
                "isAdmin should not be exposed in user list");
    }

    @Test
    @DisplayName("TASK 4 FIX: Search users endpoint returns DTOs without sensitive data")
    void testSearchUsersReturnsDTOs() throws Exception {
        String token = login("alice", "alice123");
        
        MvcResult result = mvc.perform(get("/api/users/search")
                .param("q", "alice")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        
        String responseBody = result.getResponse().getContentAsString();
        JsonNode searchResults = objectMapper.readTree(responseBody);
        
        assertTrue(searchResults.isArray(), "Search results should be an array");
        
        if (searchResults.size() > 0) {
            JsonNode firstResult = searchResults.get(0);
            assertFalse(firstResult.has("password"), 
                    "Password should not be exposed in search results");
            assertFalse(firstResult.has("role"), 
                    "Role should not be exposed in search results");
            assertFalse(firstResult.has("isAdmin"), 
                    "isAdmin should not be exposed in search results");
        }
    }

    @Test
    @DisplayName("TASK 4 FIX: Account endpoint returns DTO without ownerUserId")
    void testAccountEndpointReturnsDTOWithoutOwnerUserId() throws Exception {
        String token = login("alice", "alice123");
        
        MvcResult result = mvc.perform(get("/api/accounts/mine")
                .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        
        String responseBody = result.getResponse().getContentAsString();
        JsonNode accountsArray = objectMapper.readTree(responseBody);
        
        assertTrue(accountsArray.isArray(), "Response should be an array");
        
        if (accountsArray.size() > 0) {
            JsonNode firstAccount = accountsArray.get(0);
            
            // TASK 4 FIX: ownerUserId should NOT be exposed
            assertFalse(firstAccount.has("ownerUserId"), 
                    "ownerUserId should not be exposed in account response");
            
            // Safe fields should be present
            assertTrue(firstAccount.has("id"), "Account ID should be present");
            assertTrue(firstAccount.has("balance"), "Balance should be present");
        }
    }

    @Test
    @DisplayName("TASK 4 FIX: Created user response uses DTO without password")
    void testCreatedUserResponseUsesDTO() throws Exception {
        String bobToken = login("bob", "bob123");
        String createUserPayload = "{\"username\":\"dtotest\",\"password\":\"password123\",\"email\":\"dto@test.com\"}";
        
        MvcResult result = mvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + bobToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createUserPayload))
                .andExpect(status().isOk())
                .andReturn();
        
        String responseBody = result.getResponse().getContentAsString();
        JsonNode createdUser = objectMapper.readTree(responseBody);
        
        // TASK 4 FIX: Password should NOT be returned in response
        assertFalse(createdUser.has("password"), 
                "Password should not be returned when creating user");
        assertFalse(createdUser.has("role"), 
                "Role should not be exposed in create user response");
        assertFalse(createdUser.has("isAdmin"), 
                "isAdmin should not be exposed in create user response");
        
        assertEquals("dtotest", createdUser.get("username").asText());
    }

    // ========================================
    // TASK 6: Mass Assignment Prevention Tests
    // ========================================

    @Test
    @DisplayName("TASK 6 FIX: Cannot escalate privileges via role field in signup")
    void testCannotEscalatePrivilegesViaRoleInSignup() throws Exception {
        // Attempt to signup as ADMIN via mass assignment
        String maliciousPayload = "{\"username\":\"hacker1\",\"password\":\"password123\",\"email\":\"hack@test.com\",\"role\":\"ADMIN\",\"isAdmin\":true}";
        
        mvc.perform(post("/api/auth/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(maliciousPayload))
                .andExpect(status().isCreated());
        
        // Login as the newly created user
        String token = login("hacker1", "password123");
        
        // Attempt admin-only operation (create user)
        String createUserPayload = "{\"username\":\"victim\",\"password\":\"password123\",\"email\":\"victim@test.com\"}";
        
        // TASK 6 FIX: Should fail because user was created as USER, not ADMIN
        mvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(createUserPayload))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("Access Denied"));
    }

    @Test
    @DisplayName("TASK 6 FIX: Cannot escalate privileges via isAdmin field in user creation")
    void testCannotEscalatePrivilegesViaIsAdminField() throws Exception {
        String bobToken = login("bob", "bob123");
        
        // Admin tries to create user with isAdmin=true via mass assignment
        String maliciousPayload = "{\"username\":\"hacker2\",\"password\":\"password123\",\"email\":\"hack2@test.com\",\"role\":\"ADMIN\",\"isAdmin\":true}";
        
        MvcResult result = mvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + bobToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(maliciousPayload))
                .andExpect(status().isOk())
                .andReturn();
        
        // TASK 6 FIX: Verify that the returned user does NOT have admin privileges
        String responseBody = result.getResponse().getContentAsString();
        JsonNode createdUser = objectMapper.readTree(responseBody);
        
        // Response should not contain role or isAdmin (using DTO)
        assertFalse(createdUser.has("role"), 
                "Role should not be in response (using DTO)");
        assertFalse(createdUser.has("isAdmin"), 
                "isAdmin should not be in response (using DTO)");
        
        // Try to login and verify cannot perform admin actions
        String hackerToken = login("hacker2", "password123");
        
        String testPayload = "{\"username\":\"test\",\"password\":\"password123\",\"email\":\"test@test.com\"}";
        mvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + hackerToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(testPayload))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("TASK 6 FIX: Server controls role assignment, ignores client input")
    void testServerControlsRoleAssignment() throws Exception {
        String bobToken = login("bob", "bob123");
        
        // Try to create user with SUPERADMIN role
        String payload = "{\"username\":\"roletest\",\"password\":\"password123\",\"email\":\"role@test.com\",\"role\":\"SUPERADMIN\"}";
        
        mvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + bobToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(payload))
                .andExpect(status().isOk());
        
        // TASK 6 FIX: User should have been created with default USER role
        // Verify by attempting admin action (should fail)
        String roletestToken = login("roletest", "password123");
        
        String testPayload = "{\"username\":\"test2\",\"password\":\"password123\",\"email\":\"test2@test.com\"}";
        mvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + roletestToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(testPayload))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.message").value(
                        org.hamcrest.Matchers.anyOf(
                                org.hamcrest.Matchers.is("Access denied - admin privileges required"),
                                org.hamcrest.Matchers.is("You don't have permission to access this resource")
                        )
                ));
    }

    @Test
    @DisplayName("TASK 6 FIX: CreateUserRequest DTO only accepts safe fields")
    void testCreateUserRequestDTOOnlyAcceptsSafeFields() throws Exception {
        String bobToken = login("bob", "bob123");
        
        // Payload with only safe fields (username, password, email)
        String safePayload = "{\"username\":\"safeusr\",\"password\":\"password123\",\"email\":\"safe@test.com\"}";
        
        mvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + bobToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(safePayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("safeusr"));
        
        // Verify user was created with default privileges (cannot do admin actions)
        String safeuserToken = login("safeusr", "password123");
        
        String testPayload = "{\"username\":\"test3\",\"password\":\"password123\",\"email\":\"test3@test.com\"}";
        mvc.perform(post("/api/users")
                .header("Authorization", "Bearer " + safeuserToken)
                .contentType(MediaType.APPLICATION_JSON)
                .content(testPayload))
                .andExpect(status().isForbidden());
    }
}
