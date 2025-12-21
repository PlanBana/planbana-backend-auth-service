package com.planbana.authservice.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.Setter;

public class AuthDtos {

    @Getter
    @Setter
    public static class RegisterMinimalRequest {
        @NotBlank
        private String firebaseIdToken;

        @NotBlank
        @Size(min = 8, max = 100)
        private String password;
    }

    @Getter
    @Setter
    public static class FirebaseLoginRequest {
        @NotBlank
        private String firebaseIdToken;

        @NotBlank
        @Size(min = 8, max = 100)
        private String password;
    }

    @Getter
    @Setter
    public static class CheckPhoneRequest {
        @NotBlank
        private String firebaseIdToken;
    }

    @Getter
    @Setter
    public static class RefreshRequest {
        @NotBlank
        private String refreshToken;
    }
}
