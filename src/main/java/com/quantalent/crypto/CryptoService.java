package com.quantalent.crypto;

import com.quantalent.crypto.model.EncryptionKey;

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
     * @param encryptionKey secret key information
     * @return encrypted text if successful; otherwise return null
     */
    String encrypt(String plain, EncryptionKey encryptionKey);

    /**
     * Decrypt with password.
     *
     * @param encrypted encrypted text
     * @param encryptionKey secret key information
     * @return decrypted text if successful; otherwise return null
     */
    String decrypt(String encrypted, EncryptionKey encryptionKey);

}
