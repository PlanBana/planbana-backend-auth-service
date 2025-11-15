package com.planbana.authservice.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "firebase")
public class FirebaseProperties {
    /**
     * Path to service account JSON.
     * e.g. classpath:firebase-service-account.json OR /abs/path/firebase.json
     */
    private String config = "classpath:firebase-service-account.json";
}
