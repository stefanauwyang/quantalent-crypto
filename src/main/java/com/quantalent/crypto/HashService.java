package com.quantalent.crypto;

public interface HashService {

    /**
     * Calculate hash from given String.
     *
     * @param string input String
     * @return hash in byte array
     */
    byte[] hash(String string);

}
