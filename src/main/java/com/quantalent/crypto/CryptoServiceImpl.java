package com.quantalent.crypto;

import com.quantalent.crypto.exception.CryptoRuntimeException;
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
public class CryptoServiceImpl implements CryptoService {

    private static final String UTF_8 = "UTF-8";
    private static final String AES = "AES";
    private static final String SHA_256 = "SHA-256";

    private Logger logger = LoggerFactory.getLogger(CryptoServiceImpl.class);

    @Override
    public String encryptAes(String plain, String password) {
        if (password == null || password.length() == 0) throw new CryptoRuntimeException("Password not present");
        try {
            byte[] key = sha256(password);
            Cipher cipher = Cipher.getInstance(AES);
            SecretKey secretKey = new SecretKeySpec(key, AES);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plain.getBytes(UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new CryptoRuntimeException("Not able to do AES encryption", e);
        }
    }

    @Override
    public String encryptAes(String plain, byte[] password) {
        if (password == null || password.length == 0) throw new CryptoRuntimeException("Password not present");
        try {
            Cipher cipher = Cipher.getInstance(AES);
            SecretKey secretKey = new SecretKeySpec(password, AES);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encrypted = cipher.doFinal(plain.getBytes(UTF_8));
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            throw new CryptoRuntimeException("Not able to do AES encryption", e);
        }
    }

    @Override
    public String decryptAes(String encrypted, String password) {
        if (password == null || password.length() == 0) throw new CryptoRuntimeException("Password not present");
        try {
            byte[] key = sha256(password);
            Cipher cipher = Cipher.getInstance(AES);
            SecretKey secretKey = new SecretKeySpec(key, AES);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] plain = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            return new String(plain);
        } catch (Exception e) {
            throw new CryptoRuntimeException("Not able to do AES decryption", e);
        }
    }

    @Override
    public String decryptAes(String encrypted, byte[] password) {
        if (password == null || password.length == 0) throw new CryptoRuntimeException("Password not present");
        try {
            Cipher cipher = Cipher.getInstance(AES);
            SecretKey secretKey = new SecretKeySpec(password, AES);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] plain = cipher.doFinal(Base64.getDecoder().decode(encrypted));
            return new String(plain);
        } catch (Exception e) {
            throw new CryptoRuntimeException("Not able to do AES decryption", e);
        }
    }

    @Override
    public byte[] sha256(String string) {
        byte[] hash = null;
        if (string == null || string.length() == 0) throw new CryptoRuntimeException("Password not present");
        try {
            MessageDigest md = MessageDigest.getInstance(SHA_256);
            hash = md.digest(string.getBytes(UTF_8));
        } catch (Exception e) {
            throw new CryptoRuntimeException("Not able to do sha256 hash from given String");
        }
        return hash;
    }
}
