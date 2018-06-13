package com.quantalent.crypto.sym;

import com.quantalent.crypto.CryptoSymService;
import com.quantalent.crypto.HashService;
import com.quantalent.crypto.hash.HashServiceFactory;
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
        CryptoSymService cryptoSymService = CryptoSymServiceFactory.getInstance();
        String encrypted = cryptoSymService.encrypt(plain, passwordString);
        String decrypted = cryptoSymService.decrypt(encrypted, passwordString);

        // Output
        assertEquals("Decrypted string different than before encrypted", plain, decrypted);
    }

    /**
     * Test encrypt with password byte array and test decrypt back with AES 256 bit key.
     *
     */
    @Test
    public void testEncryptDecryptAesWithPasswordBytesAes256BitPassword() {
        HashService hashService = HashServiceFactory.getInstance();
        byte[] passwordBytes256Bit = hashService.hash(passwordString);

        // Process
        CryptoSymService cryptoSymService = CryptoSymServiceFactory.getInstance();
        String encrypted = cryptoSymService.encrypt(plain, passwordBytes256Bit);
        String decrypted = cryptoSymService.decrypt(encrypted, passwordBytes256Bit);

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
        CryptoSymService cryptoSymService = CryptoSymServiceFactory.getInstance();
        String encrypted = cryptoSymService.encrypt(plain, passwordBytes512Bit);
        String decrypted = cryptoSymService.decrypt(encrypted, passwordBytes512Bit);

        // Output
        assertEquals("Decrypted bytes different than before encrypted", plain, decrypted);
    }

}