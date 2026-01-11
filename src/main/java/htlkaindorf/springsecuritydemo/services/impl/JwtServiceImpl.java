package htlkaindorf.springsecuritydemo.services.impl;

import htlkaindorf.springsecuritydemo.exceptions.AuthorizationTokenExpiredException;
import htlkaindorf.springsecuritydemo.model.entity.User;
import htlkaindorf.springsecuritydemo.services.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    @Value("${application.security.jwt.secret}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpirationMs;

    @Value("${application.security.jwt.refresh-expiration}")
    private long refreshExpirationMs;


    @Override
    public String generateToken(User user) {
        return generateAccessToken(user);
    }

    @Override
    public String generateAccessToken(User user) {
        return Jwts.builder()
                .subject(user.getUsername())
                .claim("role", user.getRole().name())
                .claim("tokenType", "ACCESS")
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(getSigningKey())
                .compact();
    }

    @Override
    public String generateRefreshToken(User user) {
        return Jwts.builder()
                .subject(user.getUsername())
                .claim("tokenType", "REFRESH")
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + refreshExpirationMs))
                .signWith(getSigningKey())
                .compact();
    }

    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            String username = extractUsername(token);
            return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
        } catch (ExpiredJwtException e) {
            String tokenType = extractTokenTypeFromExpiredToken(e);
            throw new AuthorizationTokenExpiredException(tokenType + " is expired");
        }
    }

    @Override
    public boolean isAccessToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return "ACCESS".equals(claims.get("tokenType"));
        } catch (ExpiredJwtException e) {
            return "ACCESS".equals(extractTokenTypeFromExpiredToken(e));
        }
    }

    @Override
    public boolean isRefreshToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return "REFRESH".equals(claims.get("tokenType"));
        } catch (ExpiredJwtException e) {
            return "REFRESH".equals(extractTokenTypeFromExpiredToken(e));
        }
    }

    @Override
    public String extractUsername(String token) {
        try {
            return extractAllClaims(token).getSubject();
        } catch (ExpiredJwtException e) {
            return e.getClaims().getSubject();
        }
    }

    private String extractTokenTypeFromExpiredToken(ExpiredJwtException e) {
        Object tokenType = e.getClaims().get("tokenType");
        if ("ACCESS".equals(tokenType)) {
            return "Access token";
        } else if ("REFRESH".equals(tokenType)) {
            return "Refresh token";
        }
        return "Token";
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private boolean isTokenExpired(String token) {
        try {
            return extractAllClaims(token).getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
