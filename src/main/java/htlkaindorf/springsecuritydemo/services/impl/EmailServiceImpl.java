package htlkaindorf.springsecuritydemo.services.impl;

import htlkaindorf.springsecuritydemo.services.EmailService;
import htlkaindorf.springsecuritydemo.services.EmailTemplateService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender javaMailSender;
    private final EmailTemplateService emailTemplateService;


    @Override
    public void sendVerificationEmail(String email, String token) {

        MimeMessage message = javaMailSender.createMimeMessage();
        String verificationUrl = "http://localhost:8080/api/auth/verify-email?token=" + token;
        String htmlContent = emailTemplateService.buildVerificationEmail(email, verificationUrl);

        try {
            MimeMessageHelper messageHelper = new MimeMessageHelper(message, MimeMessageHelper.MULTIPART_MODE_MIXED_RELATED, "UTF-8");
            messageHelper.setFrom("noreply@springsecuritydemo.com");
            messageHelper.setTo(email);
            messageHelper.setSubject("Email Verification");
            messageHelper.setText(htmlContent, true);
            javaMailSender.send(message);
        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
    }

}
