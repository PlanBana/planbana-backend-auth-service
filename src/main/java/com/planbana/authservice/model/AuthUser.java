package com.planbana.authservice.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;
import java.util.Set;

/**
 * Minimal auth account stored in auth-service.
 * Profile and social info live in user-service.
 */
@Getter
@Setter
@Document("auth_users")
public class AuthUser {

    @Id
    private String id;

    /**
     * Foreign key to user-service's User.id (optional for now).
     * Lets you later align JWT sub with userId.
     */
    private String userId;

    @Indexed(unique = true, sparse = true)
    private String firebaseUid;

    /**
     * Normalized phone number (digits only). Unique within auth-service.
     */
    @Indexed(unique = true)
    private String phone;

    private String passwordHash;
    private boolean phoneVerified;

    private Set<String> roles;      // e.g., ["USER"]
    private List<String> languages; // e.g., ["English"]
}
