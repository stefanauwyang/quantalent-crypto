package com.quantalent.crypto.hash;

import com.quantalent.crypto.HashService;
import com.quantalent.crypto.exception.CryptoRuntimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;

public class Sha256HashService implements HashService {

    private static final String UTF_8 = "UTF-8";
    private static final String SHA_256 = "SHA-256";

    private Logger logger = LoggerFactory.getLogger(Sha256HashService.class);

    /**
     * Calculate SHA256 hash from given String.
     *
     * @param string input String
     * @return hash in byte array
     */
    @Override
    public byte[] hash(String string) {
        logger.debug("Calculating sha256...");
        byte[] hash;
        if (string == null || string.length() == 0) throw new CryptoRuntimeException("Password not present");
        try {
            MessageDigest md = MessageDigest.getInstance(SHA_256);
            hash = md.digest(string.getBytes(UTF_8));
            logger.debug("Success calculating sha256");
        } catch (Exception e) {
            logger.debug("Fail calculating sha256");
            throw new CryptoRuntimeException("Not able to do sha256 hash from given String");
        }
        return hash;
    }

}
