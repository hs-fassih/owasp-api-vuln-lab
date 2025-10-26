package edu.nu.owaspapivulnlab.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
// FIX(Task 1): Import BCryptPasswordEncoder for password hashing
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
// TASK 5 FIX: Import rate limiting filter to protect against API abuse
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.*;

import java.io.IOException;
import java.util.Collections;

@Configuration
public class SecurityConfig {

    @Value("${app.jwt.secret}")
    private String secret;
    
    // TASK 5 FIX: Inject rate limiting filter
    private final RateLimitingFilter rateLimitingFilter;
    
    public SecurityConfig(RateLimitingFilter rateLimitingFilter) {
        this.rateLimitingFilter = rateLimitingFilter;
    }

    // FIX(Task 1): Add PasswordEncoder bean for BCrypt password hashing
    // This replaces plaintext password storage with secure BCrypt hashes
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // FIX(Task 2): Tightened SecurityFilterChain to fix API7 Security Misconfiguration
    // Removed overly permissive permitAll on GET /api/** endpoints
    // Now requires authentication for all API endpoints except login and signup
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // CSRF disabled for stateless JWT API (acceptable for REST APIs)
        http.csrf(csrf -> csrf.disable());
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // FIX(Task 2): Properly ordered and restrictive authorization rules
        http.authorizeHttpRequests(reg -> reg
                // Public endpoints: only login, signup, and H2 console
                .requestMatchers("/api/auth/login", "/api/auth/signup").permitAll()
                .requestMatchers("/h2-console/**").permitAll()
                
                // FIX(Task 2): Admin endpoints require ADMIN role
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                
                // FIX(Task 2): All other /api/** endpoints require authentication
                // Removed the dangerous permitAll on GET requests
                .requestMatchers("/api/**").authenticated()
                
                // All other requests require authentication
                .anyRequest().authenticated()
        );

        // Allow H2 console frames
        http.headers(h -> h.frameOptions(f -> f.disable()));

        // TASK 5 FIX: Add rate limiting filter BEFORE JWT filter
        // This ensures rate limits are enforced even before JWT validation
        // Prevents attackers from overwhelming the system with invalid tokens
        http.addFilterBefore(rateLimitingFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);

        // FIX(Task 2): Add JWT filter before authentication filter
        http.addFilterBefore(new JwtFilter(secret), org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // FIX(Task 2): Enhanced JWT filter with proper error handling
    // No longer silently swallows JWT validation errors
    static class JwtFilter extends OncePerRequestFilter {
        private final String secret;
        JwtFilter(String secret) { this.secret = secret; }

        @Override
        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
                throws ServletException, IOException {
            String auth = request.getHeader("Authorization");
            if (auth != null && auth.startsWith("Bearer ")) {
                String token = auth.substring(7);
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
                    // OLD VULNERABILITY: silently continued as anonymous user
                    // NEW: explicitly reject with 401 Unauthorized
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Invalid or malformed token\"}");
                    return; // Stop the filter chain - don't continue as anonymous
                }
            }
            chain.doFilter(request, response);
        }
    }
}
