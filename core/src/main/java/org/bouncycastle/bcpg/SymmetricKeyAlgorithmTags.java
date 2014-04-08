package org.bouncycastle.bcpg;

/**
 * Basic tags for symmetric key algorithms
 */
public interface SymmetricKeyAlgorithmTags 
{
    public static final int NULL = 0;        // Plaintext or unencrypted data
    public static final int IDEA = 1;        // IDEA [IDEA]
    public static final int TRIPLE_DES = 2;  // Triple-DES (DES-EDE, as per spec -168 bit key derived from 192)
    public static final int CAST5 = 3;       // CAST5 (128 bit key, as per RFC 2144)
    public static final int BLOWFISH = 4;    // Blowfish (128 bit key, 16 rounds) [BLOWFISH]
    public static final int SAFER = 5;       // SAFER-SK128 (13 rounds) [SAFER]
    public static final int DES = 6;         // Reserved for DES/SK
    public static final int AES_128 = 7;     // Reserved for AES with 128-bit key
    public static final int AES_192 = 8;     // Reserved for AES with 192-bit key
    public static final int AES_256 = 9;     // Reserved for AES with 256-bit key
    public static final int TWOFISH = 10;    // Reserved for Twofish
    public static final int CAMELLIA_128 = 11;    // Reserved for Camellia with 128-bit key
    public static final int CAMELLIA_192 = 12;    // Reserved for Camellia with 192-bit key
    public static final int CAMELLIA_256 = 13;    // Reserved for Camellia with 256-bit key
}
