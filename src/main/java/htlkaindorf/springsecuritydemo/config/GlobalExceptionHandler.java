package htlkaindorf.springsecuritydemo.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import htlkaindorf.springsecuritydemo.exceptions.AuthorizationTokenExpiredException;
import htlkaindorf.springsecuritydemo.exceptions.InvalidRefreshTokenException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final ObjectMapper mapper;

    @ExceptionHandler(AuthorizationTokenExpiredException.class)
    public void handleTokenExpiredException(
            AuthorizationTokenExpiredException ex,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("error", "Unauthorized");
        responseBody.put("message", ex.getMessage());
        responseBody.put("status", HttpServletResponse.SC_UNAUTHORIZED);

        mapper.writeValue(response.getWriter(), responseBody);
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public void handleInvalidRefreshTokenException(
            InvalidRefreshTokenException ex,
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("error", "Unauthorized");
        responseBody.put("message", ex.getMessage());
        responseBody.put("status", HttpServletResponse.SC_UNAUTHORIZED);

        mapper.writeValue(response.getWriter(), responseBody);
    }
}
