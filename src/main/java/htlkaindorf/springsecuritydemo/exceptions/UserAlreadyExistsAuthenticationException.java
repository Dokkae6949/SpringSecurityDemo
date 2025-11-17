package htlkaindorf.springsecuritydemo.exceptions;

public class UserAlreadyExistsAuthenticationException extends RuntimeException {
  public UserAlreadyExistsAuthenticationException(String message) {super(message);}
}
