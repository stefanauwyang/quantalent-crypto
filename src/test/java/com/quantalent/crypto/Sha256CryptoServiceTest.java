package com.quantalent.crypto;

import com.quantalent.crypto.model.EncryptionKey;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class Sha256CryptoServiceTest {

    @Test
    public void testEncryptDecrypt() {
        // Input
        String plain = "Message before encryption";
        EncryptionKey encryptionKey = new EncryptionKey();
        encryptionKey.setPassword(plain);

        // Process
        CryptoService cryptoService = new Sha256CryptoService();
        String encrypted = cryptoService.encrypt(plain, encryptionKey);
        String decrypted = cryptoService.decrypt(encrypted, encryptionKey);

        // Output
        assertEquals("Decrypted string different than before encrypted", plain, decrypted);
    }
}