package com.minsait.cybersec.learning.cryptojava.exercise1;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

import java.nio.charset.Charset;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.assertEquals;

@RunWith(JUnitPlatform.class)
class CaesarCipherTest {

    @BeforeAll
    static void mainSetUp() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    void cipher_offset_1() {
        CaesarCipher testObject = new CaesarCipher(1);

        byte[] result = testObject.cipher("Javier Jeronimo_".getBytes(Charset.forName("UTF-8")));

        assertEquals("Kbwjfs!Kfspojnp`", new String(result, Charset.forName("UTF-8")));
    }

    @Test
    void cipher_offset_0() {
        CaesarCipher testObject = new CaesarCipher(0);

        byte[] result = testObject.cipher("Javier Jeronimo_".getBytes(Charset.forName("UTF-8")));

        assertEquals("Javier Jeronimo_", new String(result, Charset.forName("UTF-8")));
    }

    @Test
    void cipher_offset_90() {
        CaesarCipher testObject = new CaesarCipher(255);

        byte[] result = testObject.cipher("Javier Jeronimo_".getBytes(Charset.forName("UTF-8")));

        assertEquals("I`uhdq\u001FIdqnmhln^", new String(result, Charset.forName("UTF-8")));
    }

    @Test
    void decipher_offset_1() {
        CaesarCipher testObject = new CaesarCipher(1);

        byte[] result = testObject.decipher("Kbwjfs!Kfspojnp`".getBytes(Charset.forName("UTF-8")));

        assertEquals("Javier Jeronimo_", new String(result, Charset.forName("UTF-8")));
    }

    @Test
    void decipher_offset_0() {
        CaesarCipher testObject = new CaesarCipher(0);

        byte[] result = testObject.decipher("Javier Jeronimo_".getBytes(Charset.forName("UTF-8")));

        assertEquals("Javier Jeronimo_", new String(result, Charset.forName("UTF-8")));
    }

    @Test
    void decipher_offset_90() {
        CaesarCipher testObject = new CaesarCipher(255);

        byte[] result = testObject.decipher("I`uhdq\u001FIdqnmhln^".getBytes(Charset.forName("UTF-8")));

        assertEquals("Javier Jeronimo_", new String(result, Charset.forName("UTF-8")));
    }
}
