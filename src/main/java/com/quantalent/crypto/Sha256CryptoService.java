package com.quantalent.crypto;

import com.quantalent.crypto.exception.CryptoException;
import com.quantalent.crypto.model.EncryptionKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Cryptography functions using SHA 256 password with AES algorithm.
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
     * @param encryptionKey encryption key information
     * @return encrypted text if successful; otherwise return null
     */
    public String encrypt(String plain, EncryptionKey encryptionKey) {
        try {
            MessageDigest md = MessageDigest.getInstance(SHA_256);
            String password = encryptionKey.getPassword();
            if (password == null || password.length() == 0) throw new CryptoException("Password not present");
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
     * @param encryptionKey encryption key information
     * @return decrypted text if successful; otherwise return null
     */
    public String decrypt(String encrypted, EncryptionKey encryptionKey) {
        try {
            MessageDigest md = MessageDigest.getInstance(SHA_256);
            String password = encryptionKey.getPassword();
            if (password == null || password.length() == 0) throw new CryptoException("Password not present");
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
