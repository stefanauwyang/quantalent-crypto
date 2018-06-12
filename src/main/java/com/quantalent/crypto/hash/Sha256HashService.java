package com.quantalent.crypto.hash;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Sha256HashService extends BaseHashService {

    private static final String SHA_256 = "SHA-256";

    private static Logger logger = LoggerFactory.getLogger(Sha256HashService.class);

    public Sha256HashService() {
        super(SHA_256);
        logger.debug("Sha256HashService Initialized");
    }

    /**
     * Calculate SHA256 hash from given String.
     *
     * @param string input String
     * @return hash in byte array
     */
    @Override
    public byte[] hash(String string) {
        return super.hash(string);
    }
}
