package com.quantalent.crypto.asym;

import com.quantalent.crypto.CryptoAsymService;
import com.quantalent.crypto.exception.CryptoException;
import com.quantalent.crypto.exception.CryptoRuntimeException;
import com.quantalent.crypto.model.Algorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

public class CryptoAsymServiceFactory implements CryptoAsymService {

    private static final Logger logger = LoggerFactory.getLogger(CryptoAsymService.class);

    private String algorithm;
    private String provider;
    private KeyPair keyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    private CryptoAsymServiceFactory(String algorithm, String provider) {
        this.algorithm = algorithm;
        this.provider = provider;
    }

    public static CryptoAsymService getInstance() {
        return new CryptoAsymServiceFactory(Algorithm.KEY_RSA.getValue(), null);
    }

    public static CryptoAsymService getInstance(String algorithm) {
        if (Algorithm.KEY_RSA.getValue().equalsIgnoreCase(algorithm)) {
            return new CryptoAsymServiceFactory(algorithm, null);
        } else {
            throw new CryptoRuntimeException("Unsupported algorithm");
        }
    }

    public static CryptoAsymService getInstance(String algorithm, String provider) {
        if (Algorithm.KEY_RSA.getValue().equalsIgnoreCase(algorithm)) {
            return new CryptoAsymServiceFactory(algorithm, provider);
        } else {
            throw new CryptoRuntimeException("Unsupported algorithm");
        }
    }

    private Cipher getCipherInstance() throws CryptoException {
        try {
            if (provider == null) {
                return Cipher.getInstance(algorithm);
            } else {
                return Cipher.getInstance(algorithm, provider);
            }
        } catch (NoSuchProviderException e) {
            logger.debug("Asymmetric cipher provider error.");
            throw new CryptoException("Asymmetric cipher provider error.", e);
        } catch (Exception e) {
            logger.debug("Asymmetric cipher algorithm error.");
            throw new CryptoException("Asymmetric cipher algorithm error.", e);
        }
    }

    /**
     * Encrypt plainText using public key.
     * @see CryptoAsymServiceFactory#setPublicKey(PublicKey)
     *
     * @param plainText text to be encrypted
     * @return encrypted plainText in bytes
     * @throws CryptoException if not able to encrypt
     */
    @Override
    public byte[] encrypt(byte[] plainText) throws CryptoException {
        logger.info("Encrypting with public key...");
        byte[] cipherText;

        if (getPublicKey() == null) {
            if (getKeyPair() != null) {
                setPublicKey(getKeyPair().getPublic());
            } else {
                throw new CryptoException("Public key has not been set.");
            }
        }

        Cipher cipher = getCipherInstance();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, getPublicKey());
            int blockSize = cipher.getBlockSize();

            if (blockSize < 1) {
                logger.debug("Original blockSize: {}", blockSize);
                if (Algorithm.CIPHER_RSA_ECB_PKCS1Padding.getValue().equalsIgnoreCase(cipher.getAlgorithm())) {
                    blockSize = ((RSAPublicKey) getPublicKey()).getModulus().bitLength() / 8;
                    logger.debug("Set blockSize: {}", blockSize);
                } else if (Algorithm.KEY_RSA.getValue().equalsIgnoreCase(cipher.getAlgorithm())) {
                    blockSize = ((RSAPublicKey) getPublicKey()).getModulus().bitLength() / 8;
                    logger.debug("Set blockSize: {}", blockSize);
                } else {
                    logger.error("Unknown blockSize.");
                }
            }

            int outputSize = cipher.getOutputSize(plainText.length);
            int lastSize = plainText.length % blockSize;
            int blocksSize = lastSize != 0 ? plainText.length / blockSize + 1 : plainText.length / blockSize;

            cipherText = new byte[outputSize * blocksSize];
            int i = 0;
            while (plainText.length - i * blockSize > 0) {
                if (plainText.length - i * blockSize > blockSize)
                    cipher.doFinal(plainText, i * blockSize, blockSize, cipherText, i * outputSize);
                else
                    cipher.doFinal(plainText, i * blockSize, plainText.length - i * blockSize, cipherText, i * outputSize);
                i++;
            }
            logger.info("Success encrypt with public key");
        } catch (Exception e) {
            logger.error("Fail encrypt with public key", e);
            throw new CryptoException("Fail encrypt with public key", e);
        }
        return cipherText;
    }

    /**
     * Decrypt cipherText using private key.
     * @see CryptoAsymServiceFactory#setPublicKey(PublicKey)
     *
     * @param cipherText text to be decrypted
     * @return decrypted cipherText in bytes
     * @throws CryptoException if not able to decrypt
     */
    @Override
    public byte[] decrypt(byte[] cipherText) throws CryptoException {
        logger.info("Decrypting with private key...");
        ByteArrayOutputStream bout = null;

        if (getPrivateKey() == null) {
            if (getKeyPair() != null) {
                setPrivateKey(getKeyPair().getPrivate());
            } else {
                throw new CryptoException("Private Key has not been set.");
            }
        }

        Cipher cipher = getCipherInstance();
        boolean success = false;
        Exception exception = new Exception();
        try {
            cipher.init(Cipher.DECRYPT_MODE, getPrivateKey());

            int blockSize = cipher.getBlockSize();
            if (blockSize < 1) {
                logger.debug("Original blockSize: {}", blockSize);
                if (Algorithm.CIPHER_RSA_ECB_PKCS1Padding.getValue().equalsIgnoreCase(cipher.getAlgorithm())) {
                    blockSize = ((RSAPublicKey) getPublicKey()).getModulus().bitLength() / 8;
                    logger.debug("Set blockSize: {}", blockSize);
                } else if (Algorithm.KEY_RSA.getValue().equalsIgnoreCase(cipher.getAlgorithm())) {
                    blockSize = ((RSAPublicKey) getPublicKey()).getModulus().bitLength() / 8;
                    logger.debug("Set blockSize: {}", blockSize);
                } else {
                    logger.error("Unknown blockSize");
                }
            }

            bout = new ByteArrayOutputStream(64);
            int i = 0;
            while (cipherText.length - i * blockSize > 0) {
                bout.write(cipher.doFinal(cipherText, i * blockSize, blockSize));
                i++;
            }

            success = true;
            logger.info("Success decrypt with public key");
        } catch (Exception e) {
            exception = e;
        }

        if (!success) {
            logger.error("Fail decrypt with public key");
            throw new CryptoException("Fail decrypt with public key", exception);
        }
        return bout.toByteArray();
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
