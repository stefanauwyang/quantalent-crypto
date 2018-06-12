package com.quantalent.crypto.hash;

import com.quantalent.crypto.HashService;
import org.junit.Test;

import java.util.Base64;

import static org.junit.Assert.assertEquals;

public class Sha256HashServiceTest {

    private static final String PLAIN = "Hello";
    private static final String HASH = "GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=";

    @Test
    public void testHash() {
        HashService hashService = new Sha256HashService();
        byte[] hash = hashService.hash(PLAIN);
        String hashResult = Base64.getEncoder().encodeToString(hash);
        assertEquals("Test if sha256 calculated correctly", HASH, hashResult);
    }
}