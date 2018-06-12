package com.quantalent.crypto.helper;

import com.quantalent.crypto.Algorithm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
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

    /**
     * Load X.509 format PEM encoded Certificate
     *
     * @param filePath path to certificate file
     */
    public void loadX509Certificate(String filePath) {
        File file = new File(filePath);
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
                logger.debug("Certificate file not found");
                logger.error(e.getMessage(), e);
            } catch (CertificateException e) {
                logger.debug("Unable to generate X509 certificate from certificate file");
                logger.error(e.getMessage(), e);
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
     * @param filePath path to private key file
     */
    public void loadPrivateKey(String filePath) {
        File file = new File(filePath);
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
                logger.debug("Private key loaded", sb.toString());
            } catch (FileNotFoundException e) {
                logger.debug("Certificate file not found");
                logger.error(e.getMessage(), e);
            } catch (IOException e) {
                logger.debug("Unable to read certificate file");
                logger.error(e.getMessage(), e);
            } catch (NoSuchAlgorithmException e) {
                logger.debug("Unable to get instance of RSA algorithm");
                logger.error(e.getMessage(), e);
            } catch (InvalidKeySpecException e) {
                logger.debug("Unable to generate private key from KeySpec");
                logger.error(e.getMessage(), e);
            } finally {
                if (is != null) {
                    try { is.close(); } catch (IOException e) { }
                }
            }
        }
    }

    /**
     * Load X.509 format PEM encoded public key
     *
     * @param filePath path to public key file
     */
    public void loadPublicKey(String filePath) {
        File file = new File(filePath);
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
                logger.debug("Public key loaded", sb.toString());
            } catch (FileNotFoundException e) {
                logger.debug("Certificate file not found");
                logger.error(e.getMessage(), e);
            } catch (IOException e) {
                logger.debug("Unable to read certificate file");
                logger.error(e.getMessage(), e);
            } catch (NoSuchAlgorithmException e) {
                logger.debug("Unable to get instance of RSA algorithm");
                logger.error(e.getMessage(), e);
            } catch (InvalidKeySpecException e) {
                logger.debug("Unable to generate public key from KeySpec");
                logger.error(e.getMessage(), e);
            } finally {
                if (is != null) {
                    try { is.close(); } catch (IOException e) { }
                }
            }
        }
    }

    /**
     * Verifying text against base64 url encoded signature using publicKey.
     * @see PkiHelper#verifySignature(RSAPublicKey, String, String)
     * @see PkiHelper#setPublicKey(RSAPublicKey)
     * @see PkiHelper#verifySignature(byte[], byte[])
     *
     * @param text to be verified against signature using publicKey
     * @param signature base64 url encoded (-_ instead of +/), to be verified against text using publicKey
     */
    public boolean verifySignature(String text, String signature) {
        byte[] urlDecodedSignature = Base64.getUrlDecoder().decode(signature);
        return verifySignature(text.getBytes(), urlDecodedSignature);
    }

    /**
     * Verifying text against base64 url encoded signature using publicKey.
     * @see PkiHelper#verifySignature(String, String)
     * @see PkiHelper#setPublicKey(RSAPublicKey)
     * @see PkiHelper#verifySignature(byte[], byte[])
     *
     * @param publicKey to verify signature of a text
     * @param text to be verified against signature using publicKey
     * @param signature base64 url encoded (-_ instead of +/), to be verified against text using publicKey
     */
    public boolean verifySignature(RSAPublicKey publicKey, String text, String signature) {
        byte[] urlDecodedSignature = Base64.getUrlDecoder().decode(signature);
        return verifySignature(publicKey, text.getBytes(), urlDecodedSignature);
    }

    /**
     * Verifying bytes text against bytes signature using publicKey.
     * @see PkiHelper#setPublicKey(RSAPublicKey)
     * @see PkiHelper#verifySignature(RSAPublicKey, byte[], byte[])
     *
     * @param text to be verified against signature using publicKey
     * @param signature to be verified against text using publicKey
     */
    public boolean verifySignature(byte[] text, byte[] signature) {
        return verifySignature(publicKey, text, signature);
    }

    /**
     * Verifying bytes text against bytes signature using publicKey.
     *
     * @param publicKey to verify signature of a text
     * @param text to be verified against signature using publicKey
     * @param signature to be verified against text using publicKey
     */
    public boolean verifySignature(RSAPublicKey publicKey, byte[] text, byte[] signature) {
        boolean verify = false;
        Signature sig;
        try {
            sig = Signature.getInstance(Algorithm.SIGN_SHA256withRSA.getValue());
            sig.initVerify(publicKey);
            sig.update(text);
            verify = sig.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            logger.debug("Unable to get Signature instance using {}", Algorithm.SIGN_SHA256withRSA.getValue());
            logger.error(e.getMessage(), e);
        } catch (InvalidKeyException e) {
            logger.debug("Unable to use public key");
            logger.error(e.getMessage(), e);
        } catch (SignatureException e) {
            logger.debug("Unable to update text / verify signature. Signature not initialized properly.");
            logger.error(e.getMessage(), e);
        }
        return verify;
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
