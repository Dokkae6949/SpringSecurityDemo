package htlkaindorf.springsecuritydemo.services;

import htlkaindorf.springsecuritydemo.model.dto.auth.AuthPasswordForgotRequest;
import htlkaindorf.springsecuritydemo.model.dto.auth.AuthPasswordResetRequest;
import htlkaindorf.springsecuritydemo.model.dto.auth.AuthRequest;
import htlkaindorf.springsecuritydemo.model.dto.auth.AuthResponse;
import htlkaindorf.springsecuritydemo.model.dto.auth.JwtAuthenticationTokens;

public interface AuthService {

    JwtAuthenticationTokens login(AuthRequest request);

    void register(AuthRequest request);

    void verifyEmail(String token);

    void forgotPassword(AuthPasswordForgotRequest request);

    boolean resetPassword(String token, AuthPasswordResetRequest request);

    JwtAuthenticationTokens refreshToken(String refreshToken);
}
