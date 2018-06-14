package com.quantalent.crypto.helper;

import com.quantalent.crypto.exception.CryptoRuntimeException;
import com.quantalent.crypto.model.Algorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Base64;

/**
 * Helper class to use RSA files.
 *
 * Generate key pair:
 *   openssl genrsa -des3 -out private.pem 2048
 * Extract public key:
 *   openssl rsa -in private.pem -outform PEM -pubout -out public.pem
 * Extract unencrypted pkcs8 private key:
 *   openssl pkcs8 -topk8 -nocrypt -in private.pem -out private_pkcs8.pem
 */
public class PkiHelper {

    private static final Logger logger = LoggerFactory.getLogger(PkiHelper.class);

    private static final String X_509 = "X.509";
    private static final String PUBLIC_KEY = "PUBLIC KEY";
    private static final String PRIVATE_KEY = "PRIVATE KEY";

    private X509Certificate certificate;
    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;

    public PkiHelper() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Load X.509 format PEM encoded Certificate
     *
     * @param path path to certificate file
     */
    public void loadX509CertFromFilePath(String path) {
        File file = new File(path);
        if (file.exists()) {
            FileInputStream is = null;
            try {
                is = new FileInputStream(file);
                CertificateFactory cf = CertificateFactory.getInstance(X_509);
                certificate = (X509Certificate) cf.generateCertificate(is);
                logger.debug("Certificate loaded from file");
                publicKey = (RSAPublicKey) certificate.getPublicKey();
                logger.debug("Public key extracted from certificate");
            } catch (FileNotFoundException e) {
                logger.debug("Certificate file not found.");
                throw new CryptoRuntimeException("Certificate file not found.", e);
            } catch (CertificateException e) {
                logger.debug("Unable to generate X509 certificate from certificate file.");
                throw new CryptoRuntimeException("Unable to generate X509 certificate from certificate file.", e);
            } finally {
                if (is != null) {
                    try { is.close(); } catch (IOException e) { }
                }
            }
        }
    }

    /**
     * Load PKCS8 format PEM encoded private key
     *
     * @param path path to private key file
     */
    public void loadPrivateKeyFromFilePath(String path) {
        File file = new File(path);
        if (file.exists()) {
            FileInputStream is = null;
            try {
                is = new FileInputStream(file);
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                String line = br.readLine();
                StringBuilder sb = new StringBuilder();
                while(line != null && line.length() > 0) {
                    if (!line.contains(PRIVATE_KEY))
                        sb.append(line);
                    line = br.readLine();
                }
                logger.debug("Private key string from file: {}", sb.toString());
                byte[] b = Base64.getDecoder().decode(sb.toString());
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(b);
                privateKey = (RSAPrivateKey) KeyFactory.getInstance(Algorithm.KEY_RSA.getValue()).generatePrivate(spec);
                logger.debug("Private key loaded");
            } catch (FileNotFoundException e) {
                logger.debug("Certificate file not found.");
                throw new CryptoRuntimeException("Certificate file not found.", e);
            } catch (IOException e) {
                logger.debug("Unable to read certificate file.");
                throw new CryptoRuntimeException("Unable to read certificate file.", e);
            } catch (NoSuchAlgorithmException e) {
                logger.debug("Unable to get instance of RSA algorithm.");
                throw new CryptoRuntimeException("Unable to get instance of RSA algorithm.", e);
            } catch (InvalidKeySpecException e) {
                logger.debug("Unable to generate private key from KeySpec.");
                throw new CryptoRuntimeException("Unable to generate private key from KeySpec.", e);
            } finally {
                if (is != null) {
                    try { is.close(); } catch (IOException e) { }
                }
            }
        }
    }

    public void loadEncryptedKeyPairFromFilePath(String path, String password) {
        try {
            // Read key pair file
            PEMParser pemParser = new PEMParser(new FileReader(path));
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            KeyPair kp;
            if (object instanceof PEMEncryptedKeyPair) {
                PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) object;
                PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
                kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));
            } else {
                PEMKeyPair ukp = (PEMKeyPair) object;
                kp = converter.getKeyPair(ukp);
            }

            this.privateKey = (RSAPrivateKey) kp.getPrivate();
            this.publicKey = (RSAPublicKey) kp.getPublic();
        } catch (Exception e) {
            throw new CryptoRuntimeException("Unable to read password encrypted key pair.", e);
        }
    }

    /**
     * Load X.509 format PEM encoded public key
     *
     * @param path path to public key file
     */
    public void loadPublicKeyFromFilePath(String path) {
        File file = new File(path);
        if (file.exists()) {
            FileInputStream is = null;
            try {
                is = new FileInputStream(file);
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                String line = br.readLine();
                StringBuilder sb = new StringBuilder();
                while(line != null && line.length() > 0) {
                    if (!line.contains(PUBLIC_KEY))
                        sb.append(line);
                    line = br.readLine();
                }
                logger.debug("Public key string from file: {}", sb.toString());
                byte[] b = Base64.getDecoder().decode(sb.toString());
                X509EncodedKeySpec spec = new X509EncodedKeySpec(b);
                publicKey = (RSAPublicKey) KeyFactory.getInstance(Algorithm.KEY_RSA.getValue()).generatePublic(spec);
                logger.debug("Public key loaded");
            } catch (FileNotFoundException e) {
                logger.debug("Certificate file not found.");
                throw new CryptoRuntimeException("Certificate file not found.", e);
            } catch (IOException e) {
                logger.debug("Unable to read certificate file.");
                throw new CryptoRuntimeException("Unable to read certificate file.", e);
            } catch (NoSuchAlgorithmException e) {
                logger.debug("Unable to get instance of RSA algorithm.");
                throw new CryptoRuntimeException("Unable to get instance of RSA algorithm.", e);
            } catch (InvalidKeySpecException e) {
                logger.debug("Unable to generate public key from KeySpec.");
                throw new CryptoRuntimeException("Unable to generate public key from KeySpec.", e);
            } finally {
                if (is != null) {
                    try { is.close(); } catch (IOException e) { }
                }
            }
        }
    }

    /**
     * Load modulus and exponent into PrivateKey
     *
     * @param modulus private key modulus
     * @param exponent private key exponent
     */
    public void loadPrivateKey(BigInteger modulus, BigInteger exponent) {
        logger.debug("Load private key from modulus & exponent");
        RSAPrivateKeySpec spec = new RSAPrivateKeySpec(modulus, exponent);
        try {
            privateKey = (RSAPrivateKey) KeyFactory.getInstance(Algorithm.KEY_RSA.getValue()).generatePrivate(spec);
        } catch (InvalidKeySpecException e) {
            logger.debug("Unable to generate private key from KeySpec.");
            throw new CryptoRuntimeException("Unable to generate private key from KeySpec.", e);
        } catch (NoSuchAlgorithmException e) {
            logger.debug("Unable to get instance of RSA algorithm");
            throw new CryptoRuntimeException("Unable to get instance of RSA algorithm", e);
        }
        logger.debug("Private key loaded");
    }

    /**
     * Load modulus and exponent into PublicKey
     *
     * @param modulus public key modulus
     * @param exponent public key exponent
     */
    public void loadPublicKey(BigInteger modulus, BigInteger exponent) {
        logger.debug("Load public key from modulus & exponent");
        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        try {
            publicKey = (RSAPublicKey) KeyFactory.getInstance(Algorithm.KEY_RSA.getValue()).generatePublic(spec);
        } catch (InvalidKeySpecException e) {
            logger.debug("Unable to generate public key from KeySpec.");
            throw new CryptoRuntimeException("Unable to generate public key from KeySpec", e);
        } catch (NoSuchAlgorithmException e) {
            logger.debug("Unable to get instance of RSA algorithm.");
            throw new CryptoRuntimeException("Unable to get instance of RSA algorithm.", e);
        }
        logger.debug("Public key loaded");
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public RSAPrivateKey getPrivateKey() { return privateKey; }

    private void setPrivateKey(RSAPrivateKey privateKey) {this.privateKey = privateKey; }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
    }
}
