package com.quantalent.crypto;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class CryptoServiceImplTest {
    private static final String plain = "Message before encryption";
    private static final String passwordString = "P@ssw0rd1!";
    private static final byte[] passwordBytes = new byte[32];

    /**
     * Test encrypt with password String and test decrypt back.
     *
     */
    @Test
    public void testEncryptDecryptAesWithPasswordString() {
        // Process
        CryptoService cryptoService = new CryptoServiceImpl();
        String encrypted = cryptoService.encryptAes(plain, passwordString);
        String decrypted = cryptoService.decryptAes(encrypted, passwordString);

        // Output
        assertEquals("Decrypted string different than before encrypted", plain, decrypted);
    }

    /**
     * Test encrypt with password byte array and test decrypt back.
     *
     */
    @Test
    public void testEncryptDecryptAesWithPasswordBytes() {
        // Process
        CryptoService cryptoService = new CryptoServiceImpl();
        String encrypted = cryptoService.encryptAes(plain, passwordBytes);
        String decrypted = cryptoService.decryptAes(encrypted, passwordBytes);

        // Output
        assertEquals("Decrypted bytes different than before encrypted", plain, decrypted);
    }

}