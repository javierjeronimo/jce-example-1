package com.minsait.cybersec.learning.cryptojava.exercise1;

/**
 * Very simple Caesar cipher.
 */
public class CaesarCipher implements CipherInterface {

    private final Integer offset;

    /**
     * Creates a Caesar cipher using a given offset
     *
     * @param offset Range: [0, 255]
     */
    public CaesarCipher(final Integer offset) {
        assert (offset >= 0);
        this.offset = offset % 256;
    }

    @Override
    public byte[] cipher(byte[] input) {
        byte[] result = new byte[input.length];

        for (int i = 0; i < input.length; i++) {
            // Padding \0 are removed...
            if ((int) input[i] == 0) {
                continue;
            }
            result[i] = (byte) ((((int) input[i]) + offset) % 256);
        }

        return result;
    }

    @Override
    public byte[] decipher(byte[] input) {
        byte[] result = new byte[input.length];

        for (int i = 0; i < input.length; i++) {
            // Padding \0 are removed...
            if ((int) input[i] == 0) {
                continue;
            }
            result[i] = (byte) ((((int) input[i]) + (256 - offset)) % 256);
        }

        return result;
    }
}
