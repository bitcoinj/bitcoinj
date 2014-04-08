package org.bouncycastle.crypto.tls;

/**
 * RFC 2246
 * <p>
 * Note that the values here are implementation-specific and arbitrary. It is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class EncryptionAlgorithm
{
    public static final int NULL = 0;
    public static final int RC4_40 = 1;
    public static final int RC4_128 = 2;
    public static final int RC2_CBC_40 = 3;
    public static final int IDEA_CBC = 4;
    public static final int DES40_CBC = 5;
    public static final int DES_CBC = 6;
    public static final int _3DES_EDE_CBC = 7;

    /*
     * RFC 3268
     */
    public static final int AES_128_CBC = 8;
    public static final int AES_256_CBC = 9;

    /*
     * RFC 5289
     */
    public static final int AES_128_GCM = 10;
    public static final int AES_256_GCM = 11;

    /*
     * RFC 5932
     */
    public static final int CAMELLIA_128_CBC = 12;
    public static final int CAMELLIA_256_CBC = 13;

    /*
     * RFC 4162
     */
    public static final int SEED_CBC = 14;

    /*
     * RFC 6655
     */
    public static final int AES_128_CCM = 15;
    public static final int AES_128_CCM_8 = 16;
    public static final int AES_256_CCM = 17;
    public static final int AES_256_CCM_8 = 18;

    /*
     * RFC 6367
     */
    public static final int CAMELLIA_128_GCM = 19;
    public static final int CAMELLIA_256_GCM = 20;

    /*
     * draft-josefsson-salsa20-tls-04 
     */
    public static final int ESTREAM_SALSA20 = 100;
    public static final int SALSA20 = 101;

    /*
     * draft-agl-tls-chacha20poly1305-04
     */
    public static final int AEAD_CHACHA20_POLY1305 = 102;
}
