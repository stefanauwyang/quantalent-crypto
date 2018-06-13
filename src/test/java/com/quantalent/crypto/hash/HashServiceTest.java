package com.quantalent.crypto.hash;

import com.quantalent.crypto.HashService;
import com.quantalent.crypto.model.Algorithm;
import org.junit.Test;

import java.util.Base64;

import static org.junit.Assert.assertEquals;

public class HashServiceTest {

    private static final String PLAIN = "Hello";
    private static final String HASH = "GF+NsyJx/iX1Yab8k4suJkMG7DBO2lGAB9F2SCY4GWk=";

    @Test
    public void hash() {
        HashService hashService = HashServiceFactory.getInstance(Algorithm.HASH_SHA_256.getValue());
        byte[] hash = hashService.hash(PLAIN);
        String hashResult = Base64.getEncoder().encodeToString(hash);
        assertEquals("Test if Sha256 calculated correctly", HASH, hashResult);
    }
}