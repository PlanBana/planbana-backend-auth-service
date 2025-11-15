package com.planbana.authservice.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.jwt")
public class JwtProperties {
    /**
     * Base64-encoded secret (HS256). Example: `echo -n 'your-256-bit-secret' | base64`
     */
    private String secret = "c3VwZXJzZWNyZXRrZXk="; // default for dev only
    private long accessTokenMinutes = 15;
    private long refreshTokenDays = 7;
}
