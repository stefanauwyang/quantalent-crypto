package com.quantalent.crypto;

/**
 * Symmetric cryptography functions.
 *
 * @author Auw Yang, Stefan
 */
public interface CryptoSymService {

    /**
     * Encrypt using sym encryption algorithm with given password.
     * Password will be converted into sha256 before used.
     *
     * @param plain plain input String
     * @param password password input String
     * @return encrypted text if successful; otherwise return null
     */
    String encryptFromString(String plain, String password);

    /**
     * Encrypt using sym encryption algorithm with given password.
     *
     * @param plain plain input String
     * @param password password input byte array
     * @return encrypted text if successful; otherwise return null
     */
    String encryptFromString(String plain, byte[] password);

    /**
     * Encrypt byte array using sym encryption algorithm with given password.
     * Password will be converted into sha256 before used.
     *
     * @param plain plain input byte array
     * @param password password input String
     * @return encrypted text if successful; otherwise return null
     */
    String encrypt(byte[] plain, String password);

    /**
     * Encrypt byte array using sym encryption algorithm with given password.
     *
     * @param plain plain input byte array
     * @param password password input byte array
     * @return encrypted text if successful; otherwise return null
     */
    String encrypt(byte[] plain, byte[] password);

    /**
     * Decrypt using sym encryption algorithm with given password.
     * Password will be converted into sha256 before used.
     *
     * @param encrypted encrypted text
     * @param password password input String
     * @return decrypted text if successful; otherwise return null
     */
    String decryptToString(String encrypted, String password);

    /**
     * Decrypt using sym encryption algorithm with given password.
     *
     * @param encrypted encrypted text
     * @param password password input byte array
     * @return decrypted text if successful; otherwise return null
     */
    String decryptToString(String encrypted, byte[] password);

    /**
     * Decrypt using sym encryption algorithm with given password.
     * Password will be converted into sha256 before used.
     *
     * @param encrypted encrypted text
     * @param password password input String
     * @return decrypted byte array if successful; otherwise return null
     */
    byte[] decrypt(String encrypted, String password);

    /**
     * Decrypt using sym encryption algorithm with given password.
     *
     * @param encrypted encrypted text
     * @param password password input byte array
     * @return decrypted byte array if successful; otherwise return null
     */
    byte[] decrypt(String encrypted, byte[] password);

}
