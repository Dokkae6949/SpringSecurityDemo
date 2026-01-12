package htlkaindorf.springsecuritydemo.services;

import htlkaindorf.springsecuritydemo.model.entity.User;
import org.springframework.security.core.userdetails.UserDetails;

public interface JwtService {

    String generateToken(User user);

    String generateAccessToken(User user);

    String generateRefreshToken(User user);

    boolean isTokenValid(String token, UserDetails userDetails);

    boolean isAccessToken(String token);

    boolean isRefreshToken(String token);

    String extractUsername(String token);

}
