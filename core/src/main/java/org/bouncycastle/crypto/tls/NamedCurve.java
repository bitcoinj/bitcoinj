package org.bouncycastle.crypto.tls;

/**
 * RFC 4492 5.1.1
 * <p>
 * The named curves defined here are those specified in SEC 2 [13]. Note that many of these curves
 * are also recommended in ANSI X9.62 [7] and FIPS 186-2 [11]. Values 0xFE00 through 0xFEFF are
 * reserved for private use. Values 0xFF01 and 0xFF02 indicate that the client supports arbitrary
 * prime and characteristic-2 curves, respectively (the curve parameters must be encoded explicitly
 * in ECParameters).
 */
public class NamedCurve
{
    public static final int sect163k1 = 1;
    public static final int sect163r1 = 2;
    public static final int sect163r2 = 3;
    public static final int sect193r1 = 4;
    public static final int sect193r2 = 5;
    public static final int sect233k1 = 6;
    public static final int sect233r1 = 7;
    public static final int sect239k1 = 8;
    public static final int sect283k1 = 9;
    public static final int sect283r1 = 10;
    public static final int sect409k1 = 11;
    public static final int sect409r1 = 12;
    public static final int sect571k1 = 13;
    public static final int sect571r1 = 14;
    public static final int secp160k1 = 15;
    public static final int secp160r1 = 16;
    public static final int secp160r2 = 17;
    public static final int secp192k1 = 18;
    public static final int secp192r1 = 19;
    public static final int secp224k1 = 20;
    public static final int secp224r1 = 21;
    public static final int secp256k1 = 22;
    public static final int secp256r1 = 23;
    public static final int secp384r1 = 24;
    public static final int secp521r1 = 25;
    
    /*
     * RFC 7027
     */
    public static final int brainpoolP256r1 = 26;
    public static final int brainpoolP384r1 = 27;
    public static final int brainpoolP512r1 = 28;

    /*
     * reserved (0xFE00..0xFEFF)
     */

    public static final int arbitrary_explicit_prime_curves = 0xFF01;
    public static final int arbitrary_explicit_char2_curves = 0xFF02;

    public static boolean isValid(int namedCurve)
    {
        return (namedCurve >= sect163k1 && namedCurve <= brainpoolP512r1)
            || (namedCurve >= arbitrary_explicit_prime_curves && namedCurve <= arbitrary_explicit_char2_curves);
    }

    public static boolean refersToASpecificNamedCurve(int namedCurve)
    {
        switch (namedCurve)
        {
        case arbitrary_explicit_prime_curves:
        case arbitrary_explicit_char2_curves:
            return false;
        default:
            return true;
        }
    }
}
