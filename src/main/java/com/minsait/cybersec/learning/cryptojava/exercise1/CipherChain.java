package com.minsait.cybersec.learning.cryptojava.exercise1;

import java.util.Iterator;
import java.util.LinkedList;

/**
 * Cipher chain that can be composed of several ciphers implementing CipherInterface
 */
public class CipherChain extends LinkedList<CipherInterface> implements CipherInterface {

    @Override
    public byte[] cipher(byte[] input) throws Exception {

        byte[] intermediate = input;
        for (CipherInterface c : this) {
            intermediate = c.cipher(intermediate);
        }

        return intermediate;
    }

    @Override
    public byte[] decipher(byte[] input) throws Exception {

        byte[] intermediate = input;
        Iterator<CipherInterface> i = this.descendingIterator();
        while (i.hasNext()) {
            CipherInterface c = i.next();
            intermediate = c.decipher(intermediate);
        }

        return intermediate;
    }
}
