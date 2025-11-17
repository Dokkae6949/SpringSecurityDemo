package htlkaindorf.springsecuritydemo.services.impl;

import htlkaindorf.springsecuritydemo.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
// Wichtig um zu entscheiden wo der User gespeichert (oder geladen) wird
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    // Rückgabe von User zu UserDetails nur gecasted, weil es keine Veerbung ist sondern mit implements so behandelt wird.
    // Man kann ohne probleme zu User zurück casten und behält alle vars und methods
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findUserByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
    }

}
