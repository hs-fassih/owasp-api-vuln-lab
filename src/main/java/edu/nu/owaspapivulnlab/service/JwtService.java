package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Map;

/**
 * FIXED TASK 07: Hardened JWT Service
 * ----------------------------------------
 * - Uses strong HMAC key loaded from environment
 * - Adds issuer and audience claims
 * - Sets short expiration (e.g. 15 minutes)
 * - Validates signature, expiry, issuer, and audience
 */
@Service
public class JwtService {

    //Load secret key from environment variable or properties
    @Value("${app.jwt.secret}")
    private String secret;

    //Short token lifetime (e.g., 900 seconds = 15 minutes)
    @Value("${app.jwt.ttl-seconds:900}")
    private long ttlSeconds;

    private static final String ISSUER = "OWASP_API_VULN_LAB";
    private static final String AUDIENCE = "APP_USERS";

    //Build strong signing key
    private Key getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes());
    }

    /**
     * Issues a hardened JWT with subject, issuer, audience, and short expiry.
     */
    public String issue(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .setSubject(subject)
                .addClaims(claims)
                .setIssuer(ISSUER)
                .setAudience(AUDIENCE)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + ttlSeconds * 1000))
                .signWith(getSigningKey(), SignatureAlgorithm.HS512) //  Stronger algorithm
                .compact();
    }

    /**
     *Validate JWT signature, expiry, issuer, and audience strictly.
     */
    public boolean validate(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .requireIssuer(ISSUER)
                    .requireAudience(AUDIENCE)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            System.err.println("Token expired: " + e.getMessage());
        } catch (JwtException e) {
            System.err.println("Invalid token: " + e.getMessage());
        }
        return false;
    }

    /**
     *Extract username (subject) from a valid token.
     */
    public String extractSubject(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }
}
