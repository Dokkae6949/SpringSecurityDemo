package htlkaindorf.springsecuritydemo.database;

import htlkaindorf.springsecuritydemo.model.entity.Role;
import htlkaindorf.springsecuritydemo.model.entity.User;
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

        User regularUser = User.builder()
                .username("alice")
                .password(passwordEncoder.encode("password123"))
                .role(Role.USER)
                .build();

        User adminUser = User.builder()
                .username("bob")
                .password(passwordEncoder.encode("password123"))
                .role(Role.ADMIN)
                .build();

        User managerUser = User.builder()
                .username("charlie")
                .password(passwordEncoder.encode("password123"))
                .role(Role.MANAGER)
                .build();

        userRepository.save(regularUser);
        userRepository.save(adminUser);
        userRepository.save(managerUser);
    }
}
