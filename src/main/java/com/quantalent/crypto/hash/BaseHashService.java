package com.quantalent.crypto.hash;

import com.quantalent.crypto.HashService;
import com.quantalent.crypto.exception.CryptoRuntimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;

public abstract class BaseHashService implements HashService {

    private static final String UTF_8 = "UTF-8";

    private static Logger logger = LoggerFactory.getLogger(BaseHashService.class);
    private String algorithm;

    BaseHashService(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Calculate hash from given String with predefined algorithm.
     *
     * @param string input String
     * @return hash in byte array
     */
    @Override
    public byte[] hash(String string) {
        logger.debug("Calculating hash with algorithm {}...", algorithm);
        byte[] hash;
        if (string == null || string.length() == 0) throw new CryptoRuntimeException("No input String given to calculate hash");
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            hash = md.digest(string.getBytes(UTF_8));
            logger.debug("Success calculate hash with algorithm {}", algorithm);
        } catch (Exception e) {
            logger.debug("Fail calculate hash with algorithm {}", algorithm);
            throw new CryptoRuntimeException("Not able to do hash from given input String", e);
        }
        return hash;
    }

    protected String getAlgorithm() {
        return algorithm;
    }
}
