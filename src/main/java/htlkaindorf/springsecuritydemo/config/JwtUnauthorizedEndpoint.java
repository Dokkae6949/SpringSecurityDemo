package htlkaindorf.springsecuritydemo.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import htlkaindorf.springsecuritydemo.exceptions.UserAlreadyExistsAuthenticationException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.stereotype.Component;

import javax.naming.InsufficientResourcesException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class JwtUnauthorizedEndpoint implements AuthenticationEntryPoint {

    private final ObjectMapper mapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        response.setStatus(resolveErrorStatus(authException));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("status", resolveErrorStatus(authException));
        // Version 1: No handling of individual errors
        responseBody.put("error", resolveErrorMessage(authException));
        responseBody.put("path", request.getRequestURL());

        mapper.writeValue(response.getWriter(), responseBody);

    }

    private int resolveErrorStatus(Exception ex) {
        if (ex instanceof UserAlreadyExistsAuthenticationException)
            return HttpServletResponse.SC_CONFLICT;
        else
            return HttpServletResponse.SC_UNAUTHORIZED;
    }

    private String resolveErrorMessage(Exception ex){
        if (ex instanceof UserAlreadyExistsAuthenticationException){
            return "Access denied: A user with this email is already registered.";
        } else {
            return ex.getMessage();
        }
    }

}
