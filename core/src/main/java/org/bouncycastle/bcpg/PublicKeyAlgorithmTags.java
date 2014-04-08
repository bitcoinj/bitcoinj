package org.bouncycastle.bcpg;

/**
 * Public Key Algorithm tag numbers
 */
public interface PublicKeyAlgorithmTags 
{
    public static final int RSA_GENERAL = 1;       // RSA (Encrypt or Sign)
    public static final int RSA_ENCRYPT = 2;       // RSA Encrypt-Only
    public static final int RSA_SIGN = 3;          // RSA Sign-Only
    public static final int ELGAMAL_ENCRYPT = 16;  // Elgamal (Encrypt-Only), see [ELGAMAL]
    public static final int DSA = 17;              // DSA (Digital Signature Standard)
    public static final int EC = 18;               // Reserved for Elliptic Curve
    public static final int ECDH = 18;             // Reserved for Elliptic Curve (actual algorithm name)
    public static final int ECDSA = 19;            // Reserved for ECDSA
    public static final int ELGAMAL_GENERAL = 20;  // Elgamal (Encrypt or Sign)
    public static final int DIFFIE_HELLMAN = 21;   // Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)

    public static final int EXPERIMENTAL_1 = 100;
    public static final int EXPERIMENTAL_2 = 101;
    public static final int EXPERIMENTAL_3 = 102;
    public static final int EXPERIMENTAL_4 = 103;
    public static final int EXPERIMENTAL_5 = 104;
    public static final int EXPERIMENTAL_6 = 105;
    public static final int EXPERIMENTAL_7 = 106;
    public static final int EXPERIMENTAL_8 = 107;
    public static final int EXPERIMENTAL_9 = 108;
    public static final int EXPERIMENTAL_10 = 109;
    public static final int EXPERIMENTAL_11 = 110;
}
