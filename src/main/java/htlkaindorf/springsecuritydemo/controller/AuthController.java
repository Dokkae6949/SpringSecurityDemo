package htlkaindorf.springsecuritydemo.controller;

import htlkaindorf.springsecuritydemo.model.dto.auth.AuthPasswordForgotRequest;
import htlkaindorf.springsecuritydemo.model.dto.auth.AuthPasswordResetRequest;
import htlkaindorf.springsecuritydemo.model.dto.auth.AuthRequest;
import htlkaindorf.springsecuritydemo.model.dto.auth.AuthResponse;
import htlkaindorf.springsecuritydemo.model.dto.auth.JwtAuthenticationTokens;
import htlkaindorf.springsecuritydemo.services.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;


    @PostMapping("/login")
    public ResponseEntity<JwtAuthenticationTokens> login(
            @Valid @RequestBody AuthRequest authRequest
    ) {
        return ResponseEntity.ok(authService.login(authRequest));
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(
            @Valid @RequestBody AuthRequest authRequest
    ) {
        authService.register(authRequest);
        return ResponseEntity.ok("Successfully registered! Check Email for verification.");
    }

    @PostMapping("/refreshToken")
    public ResponseEntity<?> refreshToken(
            @RequestHeader("Authorization") String authorizationHeader
    ) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "Bad Request");
            errorResponse.put("message", "Authorization header must contain a valid Bearer token");
            errorResponse.put("status", 400);
            return ResponseEntity.badRequest().body(errorResponse);
        }

        String refreshToken = authorizationHeader.substring(7);
        return ResponseEntity.ok(authService.refreshToken(refreshToken));
    }

    @PostMapping("/forgot-pw")
    public ResponseEntity<String> forgotPassword(
            @Valid @RequestBody AuthPasswordForgotRequest request
    ) {
        authService.forgotPassword(request);
        return ResponseEntity.ok("Email sent.");
    }

    @GetMapping("/reset-pw")
    public ResponseEntity<String> resetPassword(
            @RequestParam(value = "token") String token
    ) {
        return ResponseEntity.ok("Please send post with token in req param and new password in body to /reset-pw");
    }

    @PostMapping("/reset-pw")
    public ResponseEntity<String> resetPassword(
            @RequestParam(value = "token") String token,
            @Valid@RequestBody AuthPasswordResetRequest request
    ) {
        boolean resetSuccessful = authService.resetPassword(token, request);

        if (resetSuccessful) {
            return ResponseEntity.ok("Password reset");
        } else {
            return ResponseEntity.status(400).body("Invalid token");
        }
    }

    @GetMapping("verify-email")
    public ResponseEntity<String> verifyEmail(
            @RequestParam String token
    ) {
        authService.verifyEmail(token);
        return ResponseEntity.ok("Successfully verified!");
    }

}
