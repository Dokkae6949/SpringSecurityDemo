package htlkaindorf.springsecuritydemo.database;

import htlkaindorf.springsecuritydemo.entity.Role;
import htlkaindorf.springsecuritydemo.entity.User;
import htlkaindorf.springsecuritydemo.repositories.UserRepository;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class DBLoader {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    @PostConstruct
    public void initUsers() {
        if (userRepository.count() != 0) return;

        User user1 = User.builder()
                .username("alice")
                .password(passwordEncoder.encode("password123"))
                .role(Role.USER)
                .build();

        User user2 = User.builder()
                .username("bob")
                .password(passwordEncoder.encode("password123"))
                .role(Role.ADMIN)
                .build();

        User user3 = User.builder()
                .username("charlie")
                .password(passwordEncoder.encode("password123"))
                .role(Role.MANAGER)
                .build();

        userRepository.save(user1);
        userRepository.save(user2);
        userRepository.save(user3);
    }

}
