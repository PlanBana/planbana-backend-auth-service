package com.planbana.authservice.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.cookie")
public class CookieProperties {

    /**
     * Whether to mark the access_token cookie as Secure (HTTPS-only).
     * In dev on localhost, this is typically false.
     */
    private boolean secure = false;

    /**
     * SameSite attribute for the access_token cookie, e.g. "Lax", "Strict", or "None".
     */
    private String sameSite = "Lax";
}
