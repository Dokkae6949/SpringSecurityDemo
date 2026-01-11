package htlkaindorf.springsecuritydemo.model.dto.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AuthPasswordResetRequest {
    @NotBlank
    private String newPassword;
}
