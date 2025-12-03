package htlkaindorf.springsecuritydemo.services;

import htlkaindorf.springsecuritydemo.model.entity.User;

public interface EmailVerificationService {

    public String generateVerificationToken(User user);

}
