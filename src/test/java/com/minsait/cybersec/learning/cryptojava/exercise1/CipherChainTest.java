package com.minsait.cybersec.learning.cryptojava.exercise1;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

import java.nio.charset.Charset;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

@RunWith(JUnitPlatform.class)
class CipherChainTest {

    @BeforeAll
    static void mainSetUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
    void cipher_none() throws Exception {
        CipherChain testObject = new CipherChain();

        byte[] result = testObject.cipher(new byte[]{0x00, 0x01});

        assertArrayEquals(new byte[]{0x00, 0x01}, result);
    }

    @Test
    void cipher_one() throws Exception {
        CipherChain testObject = new CipherChain();
        testObject.add(new TripleDESCipher("BC", "123456789012345678901234".getBytes(), "12345678".getBytes()));

        byte[] result = testObject.cipher("Javier Jeronimo_".getBytes(Charset.forName("UTF-8")));

        assertArrayEquals(
                new byte[]{-13, -69, 30, 77, 23, -62, -5, -117, -116, 77, -34, -51, 47, 44, -57, -94, -109, 53, -52, 47, -57, -123, -62, 107},
                result);
    }

    @Test
    void cipher_two() throws Exception {
        CipherChain testObject = new CipherChain();
        testObject.add(new CaesarCipher(1));
        testObject.add(new TripleDESCipher("BC", "123456789012345678901234".getBytes(), "12345678".getBytes()));

        byte[] result = testObject.cipher("Javier Jeronimo_".getBytes(Charset.forName("UTF-8")));

        assertArrayEquals(
                new byte[]{6, 76, -114, 7, -67, -80, 39, -3, 6, 57, 71, 78, -33, -39, 41, 67, -109, 53, -52, 47, -57, -123, -62, 107},
                result);
    }

    @Test
    void cipher_two_reverse() throws Exception {
        CipherChain testObject = new CipherChain();
        testObject.add(new TripleDESCipher("BC", "123456789012345678901234".getBytes(), "12345678".getBytes()));
        testObject.add(new CaesarCipher(1));

        byte[] result = testObject.cipher("Javier Jeronimo_".getBytes(Charset.forName("UTF-8")));

        assertArrayEquals(
                new byte[]{-12, -68, 31, 78, 24, -61, -4, -116, -115, 78, -33, -50, 48, 45, -56, -93, -108, 54, -51, 48, -56, -122, -61, 108},
                result);
    }

    @Test
    @SuppressWarnings("MismatchedQueryAndUpdateOfCollection")
    void decipher_none() throws Exception {
        CipherChain testObject = new CipherChain();

        byte[] result = testObject.cipher(new byte[]{0x00, 0x01});

        assertArrayEquals(new byte[]{0x00, 0x01}, result);
    }

    @Test
    void decipher_one() throws Exception {
        CipherChain testObject = new CipherChain();
        testObject.add(new TripleDESCipher("BC", "123456789012345678901234".getBytes(), "12345678".getBytes()));

        byte[] result = testObject.decipher(new byte[]{-13, -69, 30, 77, 23, -62, -5, -117, -116, 77, -34, -51, 47, 44, -57, -94, -109, 53, -52, 47, -57, -123, -62, 107});

        assertEquals(
                "Javier Jeronimo_",
                (new String(result, Charset.forName("UTF-8")).trim()));
    }

    @Test
    void decipher_two() throws Exception {
        CipherChain testObject = new CipherChain();
        testObject.add(new CaesarCipher(1));
        testObject.add(new TripleDESCipher("BC", "123456789012345678901234".getBytes(), "12345678".getBytes()));

        byte[] result = testObject.decipher(new byte[]{6, 76, -114, 7, -67, -80, 39, -3, 6, 57, 71, 78, -33, -39, 41, 67, -109, 53, -52, 47, -57, -123, -62, 107});

        assertEquals(
                "Javier Jeronimo_",
                (new String(result, Charset.forName("UTF-8")).trim()));
    }

    @Test
    void decipher_two_reverse() throws Exception {
        CipherChain testObject = new CipherChain();
        testObject.add(new TripleDESCipher("BC", "123456789012345678901234".getBytes(), "12345678".getBytes()));
        testObject.add(new CaesarCipher(1));

        byte[] result = testObject.decipher(new byte[]{-12, -68, 31, 78, 24, -61, -4, -116, -115, 78, -33, -50, 48, 45, -56, -93, -108, 54, -51, 48, -56, -122, -61, 108});

        assertEquals(
                "Javier Jeronimo_",
                (new String(result, Charset.forName("UTF-8")).trim()));
    }
}