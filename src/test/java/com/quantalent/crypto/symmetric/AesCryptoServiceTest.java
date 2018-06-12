package com.quantalent.crypto.symmetric;

import com.quantalent.crypto.HashService;
import com.quantalent.crypto.SymCryptoService;
import com.quantalent.crypto.hash.Sha256HashService;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class AesCryptoServiceTest {
    private static final String plain = "Message before encryption";
    private static final String passwordString = "P@ssw0rd1!";

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
     * Test encrypt with password byte array and test decrypt back with AES 256 bit key.
     *
     */
    @Test
    public void testEncryptDecryptAesWithPasswordBytesAes256BitPassword() {
        HashService hashService = new Sha256HashService();
        byte[] passwordBytes256Bit = hashService.hash(passwordString);

        // Process
        SymCryptoService symCryptoService = new AesCryptoService();
        String encrypted = symCryptoService.encrypt(plain, passwordBytes256Bit);
        String decrypted = symCryptoService.decrypt(encrypted, passwordBytes256Bit);

        // Output
        assertEquals("Decrypted bytes different than before encrypted", plain, decrypted);
    }

    /**
     * Test encrypt with password byte array exceed max size.
     *
     */
    @Test
    public void testEncryptDecryptAesWithPasswordBytesAesMax256BitPassword() {
        byte[] passwordBytes512Bit = new byte[64];

        // Process
        SymCryptoService symCryptoService = new AesCryptoService();
        String encrypted = symCryptoService.encrypt(plain, passwordBytes512Bit);
        String decrypted = symCryptoService.decrypt(encrypted, passwordBytes512Bit);

        // Output
        assertEquals("Decrypted bytes different than before encrypted", plain, decrypted);
    }

}