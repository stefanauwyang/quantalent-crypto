package com.quantalent.crypto.symmetric;

import com.quantalent.crypto.SymCryptoService;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AesCryptoServiceTest {
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
        SymCryptoService symCryptoService = new AesCryptoService();
        String encrypted = symCryptoService.encrypt(plain, passwordString);
        String decrypted = symCryptoService.decrypt(encrypted, passwordString);

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
        SymCryptoService symCryptoService = new AesCryptoService();
        String encrypted = symCryptoService.encrypt(plain, passwordBytes);
        String decrypted = symCryptoService.decrypt(encrypted, passwordBytes);

        // Output
        assertEquals("Decrypted bytes different than before encrypted", plain, decrypted);
    }

}