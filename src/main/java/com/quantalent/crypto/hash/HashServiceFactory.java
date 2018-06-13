package com.quantalent.crypto.hash;

import com.quantalent.crypto.HashService;
import com.quantalent.crypto.exception.CryptoException;
import com.quantalent.crypto.exception.CryptoRuntimeException;
import com.quantalent.crypto.model.Algorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class HashServiceFactory implements HashService {

    private static final String UTF_8 = "UTF-8";

    private static Logger logger = LoggerFactory.getLogger(HashServiceFactory.class);
    private String algorithm;
    private String provider;

    private HashServiceFactory(String algorithm, String provider) {
        this.algorithm = algorithm;
        this.provider = provider;
    }

    public static HashService getInstance() {
        return new HashServiceFactory(Algorithm.HASH_SHA_256.getValue(), null);
    }

    public static HashService getInstance(String algorithm) {
        if (Algorithm.HASH_SHA_256.getValue().equalsIgnoreCase(algorithm)) {
            return new HashServiceFactory(algorithm, null);
        } else {
            throw new CryptoRuntimeException("Unsupported algorithm");
        }
    }

    public static HashService getInstance(String algorithm, String provider) {
        if (Algorithm.HASH_SHA_256.getValue().equalsIgnoreCase(algorithm)) {
            return new HashServiceFactory(algorithm, provider);
        } else {
            return null;
        }
    }

    private MessageDigest getDigestInstance() throws CryptoException {
        try {
            if (provider == null) {
                return MessageDigest.getInstance(algorithm);
            } else {
                return MessageDigest.getInstance(algorithm, provider);
            }
        } catch (NoSuchAlgorithmException e) {
            logger.debug("Unable to get Digest instance using {}.", algorithm);
            throw new CryptoException("Unable to get Digest instance using {}.", e);
        } catch (NoSuchProviderException e) {
            logger.debug("Digest provider error.");
            throw new CryptoException("Digest provider error.", e);
        } catch (Exception e) {
            logger.debug("Digest algorithm error.");
            throw new CryptoException("Digest algorithm error.", e);
        }
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
            MessageDigest md = getDigestInstance();
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
