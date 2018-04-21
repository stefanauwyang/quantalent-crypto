package com.quantalent.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Cryptography functions using SHA 256 algorithm.
 *
 * @author Auw Yang, Stefan
 */
public class Sha256CryptoService implements CryptoService {

    private static final String SHA_256 = "SHA-256";
    private static final String AES = "AES";
    private static final String UTF_8 = "UTF-8";

    private Logger logger = LoggerFactory.getLogger(Sha256CryptoService.class);

    /**
     * Encrypt with 256 bit password using AES algorithm.
     *
     * @param plain plain input text
     * @param password secret key
     * @return encrypted text if successful; otherwise return null
     */
    public String encrypt(String plain, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance(SHA_256);
            byte[] key = md.digest(password.getBytes(UTF_8));
            Cipher cipher = Cipher.getInstance(AES);
            SecretKey secretKey = new SecretKeySpec(key, AES);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plain.getBytes(UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
        return null;
    }

    /**
     * Decrypt with 256 bit password using AES algorithm.
     *
     * @param encrypted encrypted text
     * @param password secret key
     * @return decrypted text if successful; otherwise return null
     */
    public String decrypt(String encrypted, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance(SHA_256);
            byte[] key = md.digest(password.getBytes(UTF_8));
            Cipher cipher = Cipher.getInstance(AES);
            SecretKey secretKey = new SecretKeySpec(key, AES);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] plain = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            return new String(plain);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
        return null;
    }

}
