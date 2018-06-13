package com.quantalent.crypto;

import com.quantalent.crypto.asym.IAsym;
import com.quantalent.crypto.exception.CryptoException;

/**
 * Singin & verify functions.
 *
 * @author Auw Yang, Stefan
 */
public interface SignatureAsymService extends IAsym {

    byte[] sign(byte[] plainText) throws CryptoException;

    boolean verify(byte[] plainText, byte[] signature) throws CryptoException;

    boolean verifyBase64UrlEncodedSignature(String text, String signature) throws CryptoException;

}
