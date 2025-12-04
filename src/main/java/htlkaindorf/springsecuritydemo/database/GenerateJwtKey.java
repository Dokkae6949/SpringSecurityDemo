package htlkaindorf.springsecuritydemo.database;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;

public class GenerateJwtKey {

    public static void main(String[] args) {
        SecretKey key = Jwts.SIG.HS512.key().build();
        String base64key = Encoders.BASE64.encode(key.getEncoded());
        System.out.println("Base64 Secret Key: " + base64key);
    }

}
