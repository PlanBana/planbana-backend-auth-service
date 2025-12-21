package com.planbana.authservice.controller;

import com.google.firebase.auth.FirebaseToken;
import com.planbana.authservice.config.CookieProperties;
import com.planbana.authservice.dto.AuthDtos;
import com.planbana.authservice.model.AuthUser;
import com.planbana.authservice.repository.AuthUserRepository;
import com.planbana.authservice.security.JwtService;
import com.planbana.authservice.service.FirebaseService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthUserRepository users;
    private final PasswordEncoder encoder;
    private final JwtService jwt;
    private final FirebaseService firebase;
    private final CookieProperties cookieProps;

    public AuthController(AuthUserRepository users,
            PasswordEncoder encoder,
            JwtService jwt,
            FirebaseService firebase,
            CookieProperties cookieProps) {
        this.users = users;
        this.encoder = encoder;
        this.jwt = jwt;
        this.firebase = firebase;
        this.cookieProps = cookieProps;
    }

    private static String normalizePhone(String phone) {
        if (phone == null)
            return null;
        return phone.trim()
                .replaceAll("\\s+", "")
                .replaceAll("[^0-9]", "");
    }

    private void writeAccessCookie(HttpServletResponse res, String accessToken) {
        Cookie cookie = new Cookie("access_token", accessToken);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(cookieProps.isSecure());
        cookie.setAttribute("SameSite", cookieProps.getSameSite());
        res.addCookie(cookie);
    }

    @PostMapping("/check-phone")
    public ResponseEntity<?> checkPhone(@Valid @RequestBody AuthDtos.CheckPhoneRequest req) {

        log.debug("[check-phone] Request received");

        // ---------- 1) Firebase verification ----------
        final FirebaseToken decoded;
        final String uid;
        final String phoneRaw;
        final String phone;

        try {
            log.debug("[check-phone] Verifying firebase token...");
            decoded = firebase.verifyIdToken(req.getFirebaseIdToken());
            uid = decoded.getUid();
            log.debug("[check-phone] Firebase token verified. uid={}", uid);

            log.debug("[check-phone] Fetching phone from firebase for uid={}", uid);
            phoneRaw = firebase.getUserPhone(uid);
            log.debug("[check-phone] Firebase phone raw={}", phoneRaw);

            phone = normalizePhone(phoneRaw);
            log.debug("[check-phone] Normalized phone={}", phone);

        } catch (Exception e) {
            log.error("[check-phone] Firebase verification FAILED: {}", e.getMessage(), e);
            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "error", "Firebase token invalid/expired",
                            "details", e.getMessage()));
        }

        if (phone == null || phone.isEmpty()) {
            log.warn("[check-phone] Phone missing after firebase verify. raw={}", phoneRaw);
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid Firebase token: phone missing"));
        }

        // ---------- 2) Mongo lookup ----------
        try {
            log.debug("[check-phone] Looking up auth user in DB by phone={}", phone);
            Optional<AuthUser> existing = users.findByPhone(phone);

            if (existing.isPresent()) {
                log.debug("[check-phone] User found. authUserId={}", existing.get().getId());
                return ResponseEntity.ok(Map.of(
                        "status", "LOGIN_REQUIRED",
                        "phone", phone));
            } else {
                log.debug("[check-phone] User NOT found. returning REGISTER_REQUIRED, uid={}", uid);
                return ResponseEntity.ok(Map.of(
                        "status", "REGISTER_REQUIRED",
                        "phone", phone,
                        "firebaseUid", uid));
            }

        } catch (Exception e) {
            log.error("[check-phone] Mongo lookup FAILED (DB unavailable?): {}", e.getMessage(), e);
            return ResponseEntity.status(503)
                    .body(Map.of(
                            "error", "Auth DB unavailable",
                            "details", e.getMessage()));
        }
    }

    @PostMapping("/register-minimal")
    public ResponseEntity<?> registerMinimal(@Valid @RequestBody AuthDtos.RegisterMinimalRequest req,
            HttpServletResponse res) {
        try {
            FirebaseToken decoded = firebase.verifyIdToken(req.getFirebaseIdToken());
            String uid = decoded.getUid();
            String phone = normalizePhone(firebase.getUserPhone(uid));

            if (phone == null || phone.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid Firebase token: phone missing"));
            }
            if (users.findByPhone(phone).isPresent()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Phone already registered"));
            }

            AuthUser u = new AuthUser();
            u.setFirebaseUid(uid);
            u.setPhone(phone);
            u.setPasswordHash(encoder.encode(req.getPassword()));
            u.setPhoneVerified(true);
            u.setRoles(new HashSet<>(List.of("USER")));

            if (u.getLanguages() == null || u.getLanguages().isEmpty()) {
                u.setLanguages(List.of("English"));
            }

            users.save(u);

            // Prefix roles with ROLE_ in JWT
            Set<String> jwtRoles = u.getRoles().stream()
                    .map(r -> "ROLE_" + r)
                    .collect(Collectors.toSet());

            String access = jwt.generateAccess(u.getPhone(), jwtRoles);
            String refresh = jwt.generateRefresh(u.getPhone());

            writeAccessCookie(res, access);

            return ResponseEntity.ok(Map.of(
                    "message", "Registered successfully",
                    "accessToken", access,
                    "refreshToken", refresh));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "error", "Registration failed",
                            "details", e.getMessage()));
        }
    }

    @PostMapping("/login-firebase")
    public ResponseEntity<?> loginWithFirebase(@Valid @RequestBody AuthDtos.FirebaseLoginRequest req,
            HttpServletResponse res) {
        try {
            FirebaseToken decoded = firebase.verifyIdToken(req.getFirebaseIdToken());
            String uid = decoded.getUid();
            String phone = normalizePhone(firebase.getUserPhone(uid));

            if (phone == null || phone.isEmpty()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid Firebase token: phone missing"));
            }

            Optional<AuthUser> existing = users.findByPhone(phone);
            if (existing.isEmpty()) {
                return ResponseEntity.status(404)
                        .body(Map.of("error", "User not found"));
            }

            AuthUser u = existing.get();
            if (!encoder.matches(req.getPassword(), u.getPasswordHash())) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid password"));
            }

            Set<String> jwtRoles = u.getRoles().stream()
                    .map(r -> "ROLE_" + r)
                    .collect(Collectors.toSet());

            String access = jwt.generateAccess(u.getPhone(), jwtRoles);
            String refresh = jwt.generateRefresh(u.getPhone());

            writeAccessCookie(res, access);

            return ResponseEntity.ok(Map.of(
                    "message", "Login successful",
                    "accessToken", access,
                    "refreshToken", refresh));
        } catch (Exception e) {
            return ResponseEntity.badRequest()
                    .body(Map.of(
                            "error", "Firebase token invalid/expired",
                            "details", e.getMessage()));
        }
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@Valid @RequestBody AuthDtos.RefreshRequest req,
            HttpServletResponse res) {
        String refresh = req.getRefreshToken();
        if (refresh == null || !jwt.validateToken(refresh)) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "Invalid or expired refresh token"));
        }

        String username = jwt.getUsername(refresh);

        // Load fresh roles from DB instead of reading from refresh token
        var user = users.findByPhone(username)
                .orElseThrow(() -> new RuntimeException("User not found for refresh"));

        Set<String> jwtRoles = user.getRoles().stream()
                .map(r -> "ROLE_" + r) // normalize
                .collect(Collectors.toSet());

        String newAccess = jwt.generateAccess(username, jwtRoles);
        String newRefresh = jwt.generateRefresh(username); // fine if your refresh doesn’t carry roles

        writeAccessCookie(res, newAccess);

        return ResponseEntity.ok(Map.of(
                "accessToken", newAccess,
                "refreshToken", newRefresh));
    }

}
