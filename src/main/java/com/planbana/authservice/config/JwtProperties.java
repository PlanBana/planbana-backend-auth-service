package com.planbana.authservice.config;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@Slf4j
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {

    /**
     * Base64-encoded secret (HS256).
     * MUST be overridden in real environments.
     */
    private String secret;

    /**
     * Minutes for access token validity.
     * Bound from app.jwt.access-token-minutes in application.yml
     */
    private long accessTokenMinutes;

    /**
     * Days for refresh token validity.
     * Bound from app.jwt.refresh-token-days in application.yml
     */
    private long refreshTokenDays;

    @PostConstruct
    public void validate() {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("app.jwt.secret must be provided (base64 HS256 secret).");
        }
        if ("c3VwZXJzZWNyZXRrZXk=".equals(secret)) {
            log.warn("⚠ Using default JWT secret. OK for local dev, NOT OK for prod.");
        }
        if (accessTokenMinutes <= 0) {
            throw new IllegalStateException("app.jwt.access-token-minutes must be > 0");
        }
        if (refreshTokenDays <= 0) {
            throw new IllegalStateException("app.jwt.refresh-token-days must be > 0");
        }
    }
}
