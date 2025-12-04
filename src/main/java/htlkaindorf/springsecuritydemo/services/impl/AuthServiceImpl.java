package htlkaindorf.springsecuritydemo.services.impl;

import htlkaindorf.springsecuritydemo.model.dto.auth.AuthRequest;
import htlkaindorf.springsecuritydemo.model.dto.auth.AuthResponse;
import htlkaindorf.springsecuritydemo.model.entity.Role;
import htlkaindorf.springsecuritydemo.model.entity.User;
import htlkaindorf.springsecuritydemo.model.entity.VerificationToken;
import htlkaindorf.springsecuritydemo.exceptions.EmailVerificationTokenExpired;
import htlkaindorf.springsecuritydemo.exceptions.PasswordWrongException;
import htlkaindorf.springsecuritydemo.exceptions.UserAlreadyExistsAuthenticationException;
import htlkaindorf.springsecuritydemo.exceptions.UsernameWrongException;
import htlkaindorf.springsecuritydemo.repositories.UserRepository;
import htlkaindorf.springsecuritydemo.repositories.VerificationTokenRepository;
import htlkaindorf.springsecuritydemo.services.AuthService;
import htlkaindorf.springsecuritydemo.services.EmailService;
import htlkaindorf.springsecuritydemo.services.EmailVerificationService;
import htlkaindorf.springsecuritydemo.services.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailVerificationService emailVerificationService;
    private final EmailService emailService;
    private final VerificationTokenRepository verificationTokenRepository;


    @Override
    public AuthResponse login(AuthRequest request) {

        Optional<User> userOptional = userRepository.findUserByUsername(request.getUsername());

        if (userOptional.isEmpty()) {
            throw new UsernameWrongException("User " + request.getUsername() + " not found.");
        }

        if (!passwordEncoder.matches(request.getPassword(), userOptional.get().getPassword())) {
            throw new PasswordWrongException("Invalid Password.");
        }

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                request.getUsername(),
                request.getPassword()
        ));

        UserDetails authenticatedUser = (UserDetails) authentication.getPrincipal();

        String jwt = jwtService.generateToken((User) authenticatedUser);

        return new AuthResponse(jwt);
    }

    @Override
    public void register(AuthRequest request) {
        if (userRepository.findUserByUsername(request.getUsername()).isPresent()) {
            throw new UserAlreadyExistsAuthenticationException("A user with this email is already registered.");
        }

        User registeredUser = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();

        userRepository.save(registeredUser);

        emailService.sendVerificationEmail(
                registeredUser.getUsername(),
                emailVerificationService.generateVerificationToken(registeredUser)
        );
    }

    @Override
    public void verifyEmail(String token) {
        VerificationToken verificationToken = verificationTokenRepository.getVerificationTokenByToken(token);

        if (!verificationToken.getExpiryDate().isAfter(LocalDateTime.now())) {
            throw new EmailVerificationTokenExpired("The Verification Token is expired!");
        }

        verificationToken.getUser().setEnabled(true);
        userRepository.save(verificationToken.getUser());
        verificationTokenRepository.delete(verificationToken);
    }

}
