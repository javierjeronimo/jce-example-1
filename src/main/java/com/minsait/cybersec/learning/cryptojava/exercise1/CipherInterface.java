package com.minsait.cybersec.learning.cryptojava.exercise1;

interface CipherInterface {

    byte[] cipher(byte[] input) throws Exception;

    byte[] decipher(byte[] input) throws Exception;
}
