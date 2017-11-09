package com.minsait.cybersec.learning.cryptojava.exercise1;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Triple DES cipher (DES-EEE3)
 */
public class TripleDESCipher implements CipherInterface {

    private static final String DESEDE = "DESEDE";
    private final String provider;
    private final SecretKeySpec key;
    private final IvParameterSpec ivSpec;

    /**
     * Creates a new Triple DES (EDE) cipher
     *
     * @param provider Provider ID that provides 'DESEDE' cipher
     * @param keyBytes DESEDE key bytes
     * @param ivBytes  DESEDE initialization vector bytes
     */
    public TripleDESCipher(final String provider, byte[] keyBytes, byte[] ivBytes) {
        this.provider = provider;
        this.key = new SecretKeySpec(keyBytes, DESEDE);
        this.ivSpec = new IvParameterSpec(ivBytes);
    }

    @Override
    public byte[] cipher(byte[] input) throws Exception {
        byte[] result;

        Cipher cipher = Cipher.getInstance(DESEDE, this.provider);
        cipher.init(Cipher.ENCRYPT_MODE, this.key, this.ivSpec);

        result = new byte[cipher.getOutputSize(input.length)];

        int ctLength = cipher.update(input, 0, input.length, result, 0);
        cipher.doFinal(result, ctLength);

        return result;
    }

    @Override
    public byte[] decipher(byte[] input) throws Exception {
        byte[] result;

        Cipher cipher = Cipher.getInstance(DESEDE, this.provider);
        cipher.init(Cipher.DECRYPT_MODE, this.key, this.ivSpec);

        result = new byte[cipher.getOutputSize(input.length)];

        int ptLength = cipher.update(input, 0, input.length, result, 0);
        cipher.doFinal(result, ptLength);

        return result;
    }
}
