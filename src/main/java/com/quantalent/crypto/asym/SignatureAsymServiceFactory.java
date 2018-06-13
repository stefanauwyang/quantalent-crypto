package com.quantalent.crypto.asym;

import com.quantalent.crypto.SignatureAsymService;
import com.quantalent.crypto.exception.CryptoException;
import com.quantalent.crypto.exception.CryptoRuntimeException;
import com.quantalent.crypto.model.Algorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.util.Base64;

public class SignatureAsymServiceFactory implements SignatureAsymService {

    private static final Logger logger = LoggerFactory.getLogger(SignatureAsymService.class);

    private String algorithm;
    private String provider;
    private KeyPair keyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private SignatureAsymServiceFactory(String algorithm, String provider) {
        this.algorithm = algorithm;
        this.provider = provider;
    }

    public static SignatureAsymService getInstance() {
        return new SignatureAsymServiceFactory(Algorithm.SIGN_SHA1withRSA.getValue(), null);
    }

    public static SignatureAsymService getInstance(String algorithm) {
        if (Algorithm.SIGN_SHA1withRSA.getValue().equalsIgnoreCase(algorithm)) {
            return new SignatureAsymServiceFactory(algorithm, null);
        } else if (Algorithm.SIGN_SHA256withRSA.getValue().equalsIgnoreCase(algorithm)) {
            return new SignatureAsymServiceFactory(algorithm, null);
        } else {
            throw new CryptoRuntimeException("Unsupported algorithm");
        }
    }

    public static SignatureAsymService getInstance(String algorithm, String provider) {
        if (Algorithm.SIGN_SHA1withRSA.getValue().equalsIgnoreCase(algorithm)) {
            return new SignatureAsymServiceFactory(algorithm, provider);
        } else if (Algorithm.SIGN_SHA256withRSA.getValue().equalsIgnoreCase(algorithm)) {
            return new SignatureAsymServiceFactory(algorithm, provider);
        } else {
            throw new CryptoRuntimeException("Unsupported algorithm");
        }
    }

    private Signature getSignatureInstance() throws CryptoException {
        try {
            if (provider == null) {
                return Signature.getInstance(algorithm);
            } else {
                return Signature.getInstance(algorithm, provider);
            }
        } catch (NoSuchAlgorithmException e) {
            logger.debug("Unable to get Signature instance using {}.", algorithm);
            throw new CryptoException("Unable to get Signature instance using {}.", e);
        } catch (NoSuchProviderException e) {
            logger.debug("Signature provider error.");
            throw new CryptoException("Signature provider error.", e);
        } catch (Exception e) {
            logger.debug("Signature algorithm error.");
            throw new CryptoException("Signature algorithm error.", e);
        }
    }

    /**
     * Sign plainText bytes using privateKey
     * @see SignatureAsymService#setPrivateKey(PrivateKey)
     *
     * @param plainText plainText bytes to be signed
     * @return signature bytes
     * @throws CryptoException thrown when not able to sign
     */
    public byte[] sign(byte[] plainText) throws CryptoException {
        byte[] signature;

        if (privateKey == null) {
            throw new CryptoException("Private key has not been set.");
        }

        Signature sig = getSignatureInstance();
        try {
            logger.debug("Signing signature");
            sig.initSign(privateKey);
            sig.update(plainText);
            signature = sig.sign();
            logger.debug("Signing complete");
        } catch (InvalidKeyException e) {
            logger.debug("Unable to use private key.");
            throw new CryptoException("Unable to use private key.", e);
        } catch (SignatureException e) {
            logger.debug("Unable to update text / signing. Signature not initialized properly.");
            throw new CryptoException("Unable to update text / verify signature. Signature not initialized properly.", e);
        } catch (Exception e) {
            logger.debug("Singing error.");
            throw new CryptoException("Singing error.", e);
        }
        return signature;
    }

    /**
     * Verify signature bytes of plainText bytes using publicKey
     * @see SignatureAsymService#setPublicKey(PublicKey)
     * @see SignatureAsymService#verifyBase64UrlEncodedSignature(String, String)
     *
     * @param plainText bytes to be verified against signature using publicKey
     * @param signature bytes to be verified against text using publicKey
     * @return true if signature is valid, otherwise false
     * @throws CryptoException thrown when not able to verify
     */
    @Override
    public boolean verify(byte[] plainText, byte[] signature) throws CryptoException {
        boolean verify;
        if (getPrivateKey() == null) {
            throw new CryptoException("Public key has not been set.");
        }

        try {
            logger.debug("Verifying signature");
            Signature sig = getSignatureInstance();
            sig.initVerify(publicKey);
            sig.update(plainText);
            verify = sig.verify(signature);
            logger.debug("Signature is valid? {}", verify);
        } catch (InvalidKeyException e) {
            logger.debug("Unable to use public key.");
            throw new CryptoException("Unable to use public key.", e);
        } catch (SignatureException e) {
            logger.debug("Unable to update text / verify signature. Signature not initialized properly.");
            throw new CryptoException("Unable to update text / verify signature. Signature not initialized properly.", e);
        } catch (Exception e) {
            logger.debug("Signature verify error.");
            throw new CryptoException("Signature verify error.", e);
        }
        return verify;
    }

    /**
     * Verifying text against base64 url encoded signature using publicKey.
     * @see SignatureAsymService#setPublicKey(PublicKey)
     * @see SignatureAsymService#verify(byte[], byte[])
     *
     * @param plainText String to be verified against signature using publicKey
     * @param signature String base64 url encoded (-_ instead of +/), to be verified against text using publicKey
     * @return true if signature is valid, otherwise false
     * @throws CryptoException thrown when not able to verify
     */
    @Override
    public boolean verifyBase64UrlEncodedSignature(String plainText, String signature) throws CryptoException {
        byte[] urlDecodedSignature = Base64.getUrlDecoder().decode(signature);
        return verify(plainText.getBytes(), urlDecodedSignature);
    }

    @Override
    public KeyPair getKeyPair() {
        return keyPair;
    }

    @Override
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }
}
