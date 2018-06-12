package com.quantalent.crypto;

/**
 * Asymmetric cryptography functions.
 *
 * @author Auw Yang, Stefan
 */
public interface AsymCryptoService {

    /**
     * Encrypt using asymmetric encryption algorithm.
     * Password will be converted into sha256 before used.
     *
     * @param plain plain input String
     * @param password password input String
     * @return encrypted text if successful; otherwise return null
     */
    String encrypt(String plain, String password);

    /**
     * Encrypt using asymmetric encryption algorithm.
     *
     * @param plain plain input String
     * @param password password input byte array
     * @return encrypted text if successful; otherwise return null
     */
    String encrypt(String plain, byte[] password);

    /**
     * Decrypt using asymmetric encryption algorithm.
     * Password will be converted into sha256 before used.
     *
     * @param encrypted encrypted text
     * @param password password input String
     * @return decrypted text if successful; otherwise return null
     */
    String decrypt(String encrypted, String password);

    /**
     * Decrypt using asymmetric encryption algorithm.
     *
     * @param encrypted encrypted text
     * @param password password input byte array
     * @return decrypted text if successful; otherwise return null
     */
    String decrypt(String encrypted, byte[] password);

}
