package org.bouncycastle.crypto.tls;

/**
 * RFC 2246
 * <p>
 * Note that the values here are implementation-specific and arbitrary. It is recommended not to
 * depend on the particular values (e.g. serialization).
 */
public class KeyExchangeAlgorithm
{
    public static final int NULL = 0;
    public static final int RSA = 1;
    public static final int RSA_EXPORT = 2;
    public static final int DHE_DSS = 3;
    public static final int DHE_DSS_EXPORT = 4;
    public static final int DHE_RSA = 5;
    public static final int DHE_RSA_EXPORT = 6;
    public static final int DH_DSS = 7;
    public static final int DH_DSS_EXPORT = 8;
    public static final int DH_RSA = 9;
    public static final int DH_RSA_EXPORT = 10;
    public static final int DH_anon = 11;
    public static final int DH_anon_EXPORT = 12;

    /*
     * RFC 4279
     */
    public static final int PSK = 13;
    public static final int DHE_PSK = 14;
    public static final int RSA_PSK = 15;

    /*
     * RFC 4429
     */
    public static final int ECDH_ECDSA = 16;
    public static final int ECDHE_ECDSA = 17;
    public static final int ECDH_RSA = 18;
    public static final int ECDHE_RSA = 19;
    public static final int ECDH_anon = 20;

    /*
     * RFC 5054
     */
    public static final int SRP = 21;
    public static final int SRP_DSS = 22;
    public static final int SRP_RSA = 23;
    
    /*
     * RFC 5489
     */
    public static final int ECDHE_PSK = 24;
}
