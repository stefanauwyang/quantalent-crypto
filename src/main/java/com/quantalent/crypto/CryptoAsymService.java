package com.quantalent.crypto;

import com.quantalent.crypto.asym.IAsym;
import com.quantalent.crypto.exception.CryptoException;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Asymmetric cryptography functions.
 *
 * @author Auw Yang, Stefan
 */
public interface CryptoAsymService extends IAsym {

    /**
     * Encrypt using asym encryption algorithm.
     * @see CryptoAsymService#setPublicKey(PublicKey)
     *
     * @param plainText plain input bytes
     * @return encrypted bytes if successful; otherwise return null
     */
    byte[] encrypt(byte[] plainText) throws CryptoException;

    /**
     * Decrypt using asym encryption algorithm.
     * @see CryptoAsymService#setPrivateKey(PrivateKey)
     *
     * @param cipherText encrypted bytes
     * @return decrypted bytes if successful; otherwise return null
     */
    byte[] decrypt(byte[] cipherText) throws CryptoException;

}
