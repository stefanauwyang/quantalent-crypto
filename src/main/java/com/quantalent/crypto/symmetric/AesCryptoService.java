package com.quantalent.crypto.symmetric;

import com.quantalent.crypto.HashService;
import com.quantalent.crypto.SymCryptoService;
import com.quantalent.crypto.exception.CryptoRuntimeException;
import com.quantalent.crypto.hash.Sha256HashService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * Cryptography functions using SHA 256 password with AES algorithm.
 *
 * @author Auw Yang, Stefan
 */
public class AesCryptoService implements SymCryptoService {

    private static final String UTF_8 = "UTF-8";
    private static final String AES = "AES";

    private Logger logger = LoggerFactory.getLogger(AesCryptoService.class);

    /**
     * Encrypt using AES algorithm with given password.
     * Password will be converted into sha256 before used.
     *
     * @param plain plain input String
     * @param password password input String
     * @return encrypted text if successful; otherwise return null
     */
    @Override
    public String encrypt(String plain, String password) {
        logger.debug("Encrypting using AES...");
        if (password == null || password.length() == 0) throw new CryptoRuntimeException("Password not present");
        try {
            HashService hashService = new Sha256HashService();
            logger.debug("Calculate Sha256 from password");
            byte[] key = hashService.hash(password);
            Cipher cipher = Cipher.getInstance(AES);
            SecretKey secretKey = new SecretKeySpec(key, AES);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plain.getBytes(UTF_8));
            logger.debug("Success encrypt using AES");
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            logger.debug("Fail encrypt using AES");
            throw new CryptoRuntimeException("Not able to do AES encryption", e);
        }
    }

    /**
     * Encrypt using AES algorithm with given password.
     *
     * @param plain plain input String
     * @param password password input byte array (32 bytes)
     * @return encrypted text if successful; otherwise return null
     */
    @Override
    public String encrypt(String plain, byte[] password) {
        logger.debug("Encrypting using AES...");
        if (password == null || password.length == 0) throw new CryptoRuntimeException("Password not present");
        try {
            Cipher cipher = Cipher.getInstance(AES);
            SecretKey secretKey = new SecretKeySpec(password, AES);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plain.getBytes(UTF_8));
            logger.debug("Success encrypt using AES");
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            logger.debug("Fail encrypt using AES");
            throw new CryptoRuntimeException("Not able to do AES encryption", e);
        }
    }

    /**
     * Decrypt using AES algorithm with given password.
     * Password will be converted into sha256 before used.
     *
     * @param encrypted encrypted text
     * @param password password input String
     * @return decrypted text if successful; otherwise return null
     */
    @Override
    public String decrypt(String encrypted, String password) {
        logger.debug("Decrypting using AES...");
        if (password == null || password.length() == 0) throw new CryptoRuntimeException("Password not present");
        try {
            HashService hashService = new Sha256HashService();
            logger.debug("Calculate Sha256 from password");
            byte[] key = hashService.hash(password);
            Cipher cipher = Cipher.getInstance(AES);
            SecretKey secretKey = new SecretKeySpec(key, AES);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] plain = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            logger.debug("Success decrypt using AES");
            return new String(plain);
        } catch (Exception e) {
            logger.debug("Fail decrypt using AES");
            throw new CryptoRuntimeException("Not able to do AES decryption", e);
        }
    }

    /**
     * Decrypt using AES algorithm with given password.
     *
     * @param encrypted encrypted text
     * @param password password input byte array (32 bytes)
     * @return decrypted text if successful; otherwise return null
     */
    @Override
    public String decrypt(String encrypted, byte[] password) {
        logger.debug("Decrypting using AES...");
        if (password == null || password.length == 0) throw new CryptoRuntimeException("Password not present");
        try {
            Cipher cipher = Cipher.getInstance(AES);
            SecretKey secretKey = new SecretKeySpec(password, AES);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] plain = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            logger.debug("Success decrypt using AES");
            return new String(plain);
        } catch (Exception e) {
            logger.debug("Fail decrypt using AES");
            throw new CryptoRuntimeException("Not able to do AES decryption", e);
        }
    }

}
