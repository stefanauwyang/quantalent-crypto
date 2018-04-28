package com.quantalent.crypto;

/**
 * Cryptography functions.
 *
 * @author Auw Yang, Stefan
 */
public interface CryptoService {

    /**
     * Encrypt using AES algorithm with given password.
     * Password will be converted into sha256 before used.
     *
     * @param plain plain input String
     * @param password password input String
     * @return encrypted text if successful; otherwise return null
     */
    String encryptAes(String plain, String password);

    /**
     * Encrypt using AES algorithm with given password.
     *
     * @param plain plain input String
     * @param password password input byte array
     * @return encrypted text if successful; otherwise return null
     */
    String encryptAes(String plain, byte[] password);

    /**
     * Decrypt using AES algorithm with given password.
     * Password will be converted into sha256 before used.
     *
     * @param encrypted encrypted text
     * @param password password input String
     * @return decrypted text if successful; otherwise return null
     */
    String decryptAes(String encrypted, String password);

    /**
     * Decrypt using AES algorithm with given password.
     *
     * @param encrypted encrypted text
     * @param password password input byte array
     * @return decrypted text if successful; otherwise return null
     */
    String decryptAes(String encrypted, byte[] password);

    /**
     * Calculate sha256 hash from given String.
     *
     * @param string input String
     * @return hash in byte array
     */
    byte[] sha256(String string);
}
