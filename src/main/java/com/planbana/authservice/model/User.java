package com.planbana.authservice.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.List;
import java.util.Set;

@Getter
@Setter
@Document("users")
public class User {
    @Id
    private String id;

    private String firebaseUid;
    private String phone;              // normalized E.164 (digits only)
    private String passwordHash;
    private boolean phoneVerified;

    private String name;               // optional
    private String displayName;        // optional
    private String avatarUrl;          // optional

    private Set<String> roles;         // e.g., ["USER"]
    private List<String> languages;    // e.g., ["English"]
}
