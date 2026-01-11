package htlkaindorf.springsecuritydemo.repositories;

import htlkaindorf.springsecuritydemo.model.entity.ResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface ResetTokenRepository extends JpaRepository<ResetToken, Integer> {
    @Query("select rt from ResetToken rt where rt.token = :token")
    Optional<ResetToken> findByToken(String token);
}