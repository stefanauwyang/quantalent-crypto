package com.quantalent.crypto.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PkiHandler {

    private static final Logger logger = LoggerFactory.getLogger(PkiHandler.class);

    private static final String RSA = "RSA";
    private static final String X_509 = "X.509";
    private static final String PUBLIC_KEY = "PUBLIC KEY";
    private static final String SHA_256_WITH_RSA = "SHA256withRSA";

    private X509Certificate certificate;
    private RSAPublicKey publicKey;

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
                publicKey = (RSAPublicKey) KeyFactory.getInstance(RSA).generatePublic(spec);
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
     * @see PkiHandler#verifySignature(RSAPublicKey, String, String)
     * @see PkiHandler#setPublicKey(RSAPublicKey)
     * @see PkiHandler#verifySignature(byte[], byte[])
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
     * @see PkiHandler#verifySignature(String, String)
     * @see PkiHandler#setPublicKey(RSAPublicKey)
     * @see PkiHandler#verifySignature(byte[], byte[])
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
     * @see PkiHandler#setPublicKey(RSAPublicKey)
     * @see PkiHandler#verifySignature(RSAPublicKey, byte[], byte[])
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
            sig = Signature.getInstance(SHA_256_WITH_RSA);
            sig.initVerify(publicKey);
            sig.update(text);
            verify = sig.verify(signature);
        } catch (NoSuchAlgorithmException e) {
            logger.debug("Unable to get Signature instance using {}", SHA_256_WITH_RSA);
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

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
    }
}
