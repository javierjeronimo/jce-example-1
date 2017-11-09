package com.minsait.cybersec.learning.cryptojava.exercise1;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

import javax.crypto.NoSuchPaddingException;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

@RunWith(JUnitPlatform.class)
class TripleDESCipherTest {

    private TripleDESCipher testObject;

    @BeforeAll
    static void mainSetUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    void setUp() throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
        byte[] keyBytes = "123456789012345678901234".getBytes();
        byte[] ivBytes = "12345678".getBytes();

        this.testObject = new TripleDESCipher("BC", keyBytes, ivBytes);
    }

    @org.junit.jupiter.api.Test
    void cipher() throws Exception {
        byte[] result = this.testObject.cipher("Javier Jeronimo_".getBytes(Charset.forName("UTF-8")));

        assertArrayEquals(
                new byte[]{-13, -69, 30, 77, 23, -62, -5, -117, -116, 77, -34, -51, 47, 44, -57, -94, -109, 53, -52, 47, -57, -123, -62, 107},
                result);
    }

    @org.junit.jupiter.api.Test
    void decipher() throws Exception {
        byte[] result = this.testObject.decipher(new byte[]{-13, -69, 30, 77, 23, -62, -5, -117, -116, 77, -34, -51, 47, 44, -57, -94, -109, 53, -52, 47, -57, -123, -62, 107});

        String resultString = new String(result, Charset.forName("UTF-8"));
        assertEquals("Javier Jeronimo_", resultString.trim());
    }
}
