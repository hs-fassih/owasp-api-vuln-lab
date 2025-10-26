package edu.nu.owaspapivulnlab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
// FIX(Task 1): Import PasswordEncoder for hashing passwords during data seeding
import org.springframework.security.crypto.password.PasswordEncoder;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

@Configuration
public class DataSeeder {
    // FIX(Task 1): Inject PasswordEncoder to hash passwords before saving to database
    @Bean
    CommandLineRunner seed(AppUserRepository users, AccountRepository accounts, PasswordEncoder encoder) {
        return args -> {
            if (users.count() == 0) {
                // FIX(Task 1): Hash passwords using BCrypt before saving users
                // This replaces plaintext "alice123" and "bob123" with secure BCrypt hashes
                AppUser u1 = users.save(AppUser.builder()
                        .username("alice")
                        .password(encoder.encode("alice123"))  // BCrypt hash instead of plaintext
                        .email("alice@cydea.tech")
                        .role("USER")
                        .isAdmin(false)
                        .build());
                
                AppUser u2 = users.save(AppUser.builder()
                        .username("bob")
                        .password(encoder.encode("bob123"))  // BCrypt hash instead of plaintext
                        .email("bob@cydea.tech")
                        .role("ADMIN")
                        .isAdmin(true)
                        .build());
                
                accounts.save(Account.builder().ownerUserId(u1.getId()).iban("PK00-ALICE").balance(1000.0).build());
                accounts.save(Account.builder().ownerUserId(u2.getId()).iban("PK00-BOB").balance(5000.0).build());
            }
        };
    }
}
