package com.quantalent.crypto;

/**
 * Cryptography functions.
 *
 * @author Auw Yang, Stefan
 */
public interface SymCryptoService {

    /**
     * Encrypt using symmetric encryption algorithm with given password.
     * Password will be converted into sha256 before used.
     *
     * @param plain plain input String
     * @param password password input String
     * @return encrypted text if successful; otherwise return null
     */
    String encrypt(String plain, String password);

    /**
     * Encrypt using symmetric encryption algorithm with given password.
     *
     * @param plain plain input String
     * @param password password input byte array
     * @return encrypted text if successful; otherwise return null
     */
    String encrypt(String plain, byte[] password);

    /**
     * Decrypt using symmetric encryption algorithm with given password.
     * Password will be converted into sha256 before used.
     *
     * @param encrypted encrypted text
     * @param password password input String
     * @return decrypted text if successful; otherwise return null
     */
    String decrypt(String encrypted, String password);

    /**
     * Decrypt using symmetric encryption algorithm with given password.
     *
     * @param encrypted encrypted text
     * @param password password input byte array
     * @return decrypted text if successful; otherwise return null
     */
    String decrypt(String encrypted, byte[] password);

}
