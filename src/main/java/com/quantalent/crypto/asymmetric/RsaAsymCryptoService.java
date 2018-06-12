package com.quantalent.crypto.asymmetric;

import com.quantalent.crypto.Algorithm;
import com.quantalent.crypto.exception.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

public class RsaAsymCryptoService extends BaseAsymCryptoService {

    private static final Logger logger = LoggerFactory.getLogger(RsaAsymCryptoService.class);

    private KeyPair keyPair;
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RsaAsymCryptoService() {
        super(Algorithm.KEY_RSA.getValue());
    }

    public RsaAsymCryptoService(String provider) {
        super(Algorithm.KEY_RSA.getValue(), provider);
    }

    @Override
    public byte[] encrypt(byte[] plainText) throws CryptoException {
        byte[] cipherText;

        if (this.publicKey == null) {
            if (this.keyPair != null) {
                this.publicKey = this.keyPair.getPublic();
            } else {
                throw new CryptoException("Public key has not been set.");
            }
        }

        Cipher cipher = getCipherInstance();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            int blockSize = cipher.getBlockSize();

            if (blockSize < 1) {
                logger.debug("Original blockSize: {}", blockSize);
                if (Algorithm.CIPHER_RSA_ECB_PKCS1Padding.getValue().equalsIgnoreCase(cipher.getAlgorithm())) {
                    blockSize = ((RSAPublicKey) publicKey).getModulus().bitLength() / 8;
                    logger.debug("Set blockSize: {}", blockSize);
                } else if (Algorithm.KEY_RSA.getValue().equalsIgnoreCase(cipher.getAlgorithm())) {
                    blockSize = ((RSAPublicKey) publicKey).getModulus().bitLength() / 8;
                    logger.debug("Set blockSize: {}", blockSize);
                } else {
                    logger.error("Unknown blockSize");
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
        } catch (Exception ex) {
            logger.debug("Asymmetric cipher encryption error");
            throw new CryptoException("Asymmetric cipher encryption error", ex);
        }
        return cipherText;
    }

    @Override
    public byte[] decrypt(byte[] cipherText) throws CryptoException {
        ByteArrayOutputStream bout = null;

        if (this.privateKey == null) {
            if (this.keyPair != null) {
                this.privateKey = this.keyPair.getPrivate();
            } else {
                throw new CryptoException("Private Key has not been set.");
            }
        }

        Cipher cipher = getCipherInstance();
        boolean success = false;
        Exception exception = new Exception();
        try {
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            int blockSize = cipher.getBlockSize();
            if (blockSize < 1) {
                logger.debug("Original blockSize: {}", blockSize);
                if (Algorithm.CIPHER_RSA_ECB_PKCS1Padding.getValue().equalsIgnoreCase(cipher.getAlgorithm())) {
                    blockSize = ((RSAPublicKey) publicKey).getModulus().bitLength() / 8;
                    logger.debug("Set blockSize: {}", blockSize);
                } else if (Algorithm.KEY_RSA.getValue().equalsIgnoreCase(cipher.getAlgorithm())) {
                    blockSize = ((RSAPublicKey) publicKey).getModulus().bitLength() / 8;
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
        } catch (Exception ex) {
            exception = ex;
        }

        if (!success) {
            throw new CryptoException("Asymmetric cipher decryption error: ", exception);
        }
        return bout.toByteArray();
    }

    private Cipher getCipherInstance() throws CryptoException {
        try {
            if (getProvider() == null) {
                return Cipher.getInstance(getAlgorithm());
            } else {
                return Cipher.getInstance(getAlgorithm(), getProvider());
            }
        } catch (NoSuchProviderException ex) {
            logger.debug("Asymmetric cipher provider error");
            throw new CryptoException("Asymmetric cipher provider error", ex);
        } catch (Exception ex) {
            logger.debug("Asymmetric cipher algorithm error");
            throw new CryptoException("Asymmetric cipher algorithm error", ex);
        }
    }

    @Override
    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    @Override
    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

}
