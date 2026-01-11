package htlkaindorf.springsecuritydemo.controller;

import htlkaindorf.springsecuritydemo.model.dto.auth.AuthPasswordForgotRequest;
import htlkaindorf.springsecuritydemo.model.dto.auth.AuthPasswordResetRequest;
import htlkaindorf.springsecuritydemo.model.dto.auth.AuthRequest;
import htlkaindorf.springsecuritydemo.model.dto.auth.AuthResponse;
import htlkaindorf.springsecuritydemo.services.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;


    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
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
