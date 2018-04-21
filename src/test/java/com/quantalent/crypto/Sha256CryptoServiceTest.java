package com.quantalent.crypto;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class Sha256CryptoServiceTest {

    @Test
    public void testEncryptDecrypt() {
        // Input
        String plain = "Message before encryption";

        // Process
        CryptoService cryptoService = new Sha256CryptoService();
        String encrypted = cryptoService.encrypt(plain, "password");
        String decrypted = cryptoService.decrypt(encrypted, "password");

        // Output
        assertEquals("Decrypted string different than before encrypted", plain, decrypted);
    }
}