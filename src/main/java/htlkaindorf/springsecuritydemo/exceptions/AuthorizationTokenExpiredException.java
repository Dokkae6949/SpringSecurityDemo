package htlkaindorf.springsecuritydemo.exceptions;

import org.springframework.security.core.AuthenticationException;

public class AuthorizationTokenExpiredException extends AuthenticationException {
    public AuthorizationTokenExpiredException(String message) {
        super(message);
    }
}
