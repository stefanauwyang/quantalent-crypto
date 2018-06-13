package com.quantalent.crypto.sym;

import com.quantalent.crypto.CryptoSymService;
import com.quantalent.crypto.HashService;
import com.quantalent.crypto.exception.CryptoException;
import com.quantalent.crypto.exception.CryptoRuntimeException;
import com.quantalent.crypto.hash.HashServiceFactory;
import com.quantalent.crypto.model.Algorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Cryptography functions using SHA 256 password with AES algorithm.
 *
 * @author Auw Yang, Stefan
 */
public class CryptoSymServiceFactory implements CryptoSymService {

    private Logger logger = LoggerFactory.getLogger(CryptoSymServiceFactory.class);

    private static final String UTF_8 = "UTF-8";
    private static final int MAX_PWD_BYTE_SIZE = 32; // 32 bytes = 256 bits

    private String algorithm;
    private String provider;

    private CryptoSymServiceFactory(String algorithm, String provider) {
        this.algorithm = algorithm;
        this.provider = provider;
    }

    public static CryptoSymService getInstance() {
        return new CryptoSymServiceFactory(Algorithm.KEY_AES.getValue(), null);
    }

    public static CryptoSymService getInstance(String algorithm) {
        if (Algorithm.KEY_AES.getValue().equalsIgnoreCase(algorithm)) {
            return new CryptoSymServiceFactory(algorithm, null);
        } else {
            throw new CryptoRuntimeException("Unsupported algorithm");
        }
    }

    public static CryptoSymService getInstance(String algorithm, String provider) {
        if (Algorithm.KEY_AES.getValue().equalsIgnoreCase(algorithm)) {
            return new CryptoSymServiceFactory(algorithm, provider);
        } else {
            throw new CryptoRuntimeException("Unsupported algorithm");
        }
    }

    private Cipher getCipherInstance() throws CryptoException {
        try {
            if (provider == null) {
                return Cipher.getInstance(algorithm);
            } else {
                return Cipher.getInstance(algorithm, provider);
            }
        } catch (NoSuchAlgorithmException e) {
            logger.debug("Unable to get Cipher instance using {}.", algorithm);
            throw new CryptoException("Unable to get Cipher instance using {}.", e);
        } catch (NoSuchProviderException e) {
            logger.debug("Cipher provider error.");
            throw new CryptoException("Cipher provider error.", e);
        } catch (Exception e) {
            logger.debug("Cipher algorithm error.");
            throw new CryptoException("Cipher algorithm error.", e);
        }
    }

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
            HashService hashService = HashServiceFactory.getInstance(Algorithm.HASH_SHA_256.getValue());
            logger.debug("Calculate Sha256 from password");
            byte[] key = hashService.hash(password);
            Cipher cipher = getCipherInstance();
            SecretKey secretKey = new SecretKeySpec(key, algorithm);
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
     * @param password password input byte array (128,192,256 bits / 16,24,32 bytes)
     * @return encrypted text if successful; otherwise return null
     */
    @Override
    public String encrypt(String plain, byte[] password) {
        logger.debug("Encrypting using AES...");
        if (password == null || password.length == 0) throw new CryptoRuntimeException("Password not present");
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            // Truncate if password is more than max key bit size
            if (password.length > MAX_PWD_BYTE_SIZE ) logger.warn("Password length is more than {}. Truncating...", MAX_PWD_BYTE_SIZE);
            byte[] passwordToBeUsed = Arrays.copyOf(password, password.length > MAX_PWD_BYTE_SIZE ? MAX_PWD_BYTE_SIZE : password.length);
            SecretKey secretKey = new SecretKeySpec(passwordToBeUsed, algorithm);
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
            HashService hashService = HashServiceFactory.getInstance(Algorithm.HASH_SHA_256.getValue());
            logger.debug("Calculate Sha256 from password");
            byte[] key = hashService.hash(password);
            Cipher cipher = Cipher.getInstance(algorithm);
            SecretKey secretKey = new SecretKeySpec(key, algorithm);
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
     * @param password password input byte array (128,192,256 bits / 16,24,32 bytes)
     * @return decrypted text if successful; otherwise return null
     */
    @Override
    public String decrypt(String encrypted, byte[] password) {
        logger.debug("Decrypting using AES...");
        if (password == null || password.length == 0) throw new CryptoRuntimeException("Password not present");
        try {
            Cipher cipher = Cipher.getInstance(algorithm);
            // Truncate if password is more than max key bit size
            if (password.length > MAX_PWD_BYTE_SIZE ) logger.warn("Password length is more than {}. Truncating...", MAX_PWD_BYTE_SIZE);
            byte[] passwordToBeUsed = Arrays.copyOf(password, password.length > MAX_PWD_BYTE_SIZE ? MAX_PWD_BYTE_SIZE : password.length);
            SecretKey secretKey = new SecretKeySpec(passwordToBeUsed, algorithm);
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
