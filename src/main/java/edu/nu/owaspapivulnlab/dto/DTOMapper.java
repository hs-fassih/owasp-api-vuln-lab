package edu.nu.owaspapivulnlab.dto;

import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;

import java.util.List;
import java.util.stream.Collectors;

/**
 * FIX(Task 4): DTO Mapper utility class
 * Provides methods to convert entities to DTOs, preventing sensitive data exposure
 * This ensures consistent data transformation across all controllers
 */
public class DTOMapper {
    
    /**
     * FIX(Task 4): Convert AppUser entity to UserResponseDTO
     * Excludes sensitive fields: password, role, isAdmin
     * 
     * @param user The user entity from database
     * @return Safe DTO for API responses
     */
    public static UserResponseDTO toUserDTO(AppUser user) {
        if (user == null) {
            return null;
        }
        return UserResponseDTO.builder()
                .id(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .build();
    }
    
    /**
     * FIX(Task 4): Convert list of AppUser entities to list of UserResponseDTOs
     * 
     * @param users List of user entities
     * @return List of safe DTOs for API responses
     */
    public static List<UserResponseDTO> toUserDTOList(List<AppUser> users) {
        if (users == null) {
            return null;
        }
        return users.stream()
                .map(DTOMapper::toUserDTO)
                .collect(Collectors.toList());
    }
    
    /**
     * FIX(Task 4): Convert Account entity to AccountResponseDTO
     * Excludes internal fields: ownerUserId
     * 
     * @param account The account entity from database
     * @return Safe DTO for API responses
     */
    public static AccountResponseDTO toAccountDTO(Account account) {
        if (account == null) {
            return null;
        }
        return AccountResponseDTO.builder()
                .id(account.getId())
                .iban(account.getIban())
                .balance(account.getBalance())
                .build();
    }
    
    /**
     * FIX(Task 4): Convert list of Account entities to list of AccountResponseDTOs
     * 
     * @param accounts List of account entities
     * @return List of safe DTOs for API responses
     */
    public static List<AccountResponseDTO> toAccountDTOList(List<Account> accounts) {
        if (accounts == null) {
            return null;
        }
        return accounts.stream()
                .map(DTOMapper::toAccountDTO)
                .collect(Collectors.toList());
    }
}
