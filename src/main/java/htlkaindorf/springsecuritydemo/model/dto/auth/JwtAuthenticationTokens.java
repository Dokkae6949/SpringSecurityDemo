package htlkaindorf.springsecuritydemo.model.dto.auth;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JwtAuthenticationTokens {

    private String accessToken;
    private String refreshToken;

}
