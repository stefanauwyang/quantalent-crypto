package com.quantalent.crypto;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Utility class to perform cryptography functions.
 *
 * @author Auw Yang, Stefan
 */
public class CryptoUtil {

    private Logger logger = LoggerFactory.getLogger(CryptoUtil.class);

    /**
     * Encrypt with 256 bit password using AES algorithm.
     *
     * @param plain plain input text
     * @param password secret key
     * @return encrypted text if successful; otherwise return null
     */
    public String encryptAes256(String plain, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] key = md.digest(password.getBytes("UTF-8"));
            Cipher cipher = Cipher.getInstance("AES");
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plain.getBytes("UTF-8"));
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
    public String decryptAes256(String encrypted, String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] key = md.digest(password.getBytes("UTF-8"));
            Cipher cipher = Cipher.getInstance("AES");
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] plain = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            return new String(plain);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
        return null;
    }

}
