package com.quantalent.crypto;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class CryptoUtilTest {

    @Test
    public void testEncryptDecrypt() {
        // Input
        String plain = "Message before encryption";

        // Process
        CryptoUtil cryptoUtil = new CryptoUtil();
        String encrypted = cryptoUtil.encryptAes256(plain, "password");
        String decrypted = cryptoUtil.decryptAes256(encrypted, "password");

        // Output
        assertEquals(plain, decrypted);
    }
}