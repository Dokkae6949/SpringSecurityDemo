package htlkaindorf.springsecuritydemo.repositories;

import htlkaindorf.springsecuritydemo.model.entity.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface VerificationTokenRepository extends JpaRepository<VerificationToken, Long> {

    VerificationToken getVerificationTokenByToken(String token);

    List<VerificationToken> getVerificationTokensByExpiryDateBefore(LocalDateTime expiryDateBefore);

}
