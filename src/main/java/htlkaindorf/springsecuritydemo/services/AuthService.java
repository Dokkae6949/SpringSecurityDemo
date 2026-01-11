package htlkaindorf.springsecuritydemo.services;

import htlkaindorf.springsecuritydemo.model.dto.auth.AuthPasswordForgotRequest;
import htlkaindorf.springsecuritydemo.model.dto.auth.AuthPasswordResetRequest;
import htlkaindorf.springsecuritydemo.model.dto.auth.AuthRequest;
import htlkaindorf.springsecuritydemo.model.dto.auth.AuthResponse;

public interface AuthService {

    AuthResponse login(AuthRequest request);

    void register(AuthRequest request);

    void verifyEmail(String token);

    void forgotPassword(AuthPasswordForgotRequest request);

    boolean resetPassword(String token, AuthPasswordResetRequest request);
}
