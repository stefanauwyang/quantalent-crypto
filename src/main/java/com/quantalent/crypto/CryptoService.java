package com.quantalent.crypto;

/**
 * Cryptography functions.
 *
 * @author Auw Yang, Stefan
 */
public interface CryptoService {

    /**
     * Encrypt with password.
     *
     * @param plain plain input text
     * @param password secret key
     * @return encrypted text if successful; otherwise return null
     */
    String encrypt(String plain, String password);

    /**
     * Decrypt with password.
     *
     * @param encrypted encrypted text
     * @param password secret key
     * @return decrypted text if successful; otherwise return null
     */
    String decrypt(String encrypted, String password);

}
