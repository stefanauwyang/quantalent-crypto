package com.quantalent.crypto;

import com.quantalent.crypto.exception.CryptoException;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Asymmetric cryptography functions.
 *
 * @author Auw Yang, Stefan
 */
public interface AsymCryptoService {

    /**
     * Encrypt using asymmetric encryption algorithm.
     * @see AsymCryptoService#setPublicKey(PublicKey)
     *
     * @param plainText plain input bytes
     * @return encrypted bytes if successful; otherwise return null
     */
    byte[] encrypt(byte[] plainText) throws CryptoException;

    /**
     * Decrypt using asymmetric encryption algorithm.
     * @see AsymCryptoService#setPrivateKey(PrivateKey)
     *
     * @param cipherText encrypted bytes
     * @return decrypted bytes if successful; otherwise return null
     */
    byte[] decrypt(byte[] cipherText) throws CryptoException;

    void setKeyPair(KeyPair keyPair);

    void setPrivateKey(PrivateKey privateKey);

    void setPublicKey(PublicKey publicKey);

}
