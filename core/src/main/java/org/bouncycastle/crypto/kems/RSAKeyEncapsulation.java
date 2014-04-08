package org.bouncycastle.crypto.kems;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.KeyEncapsulation;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.BigIntegers;

/**
 * The RSA Key Encapsulation Mechanism (RSA-KEM) from ISO 18033-2.
 */
public class RSAKeyEncapsulation
    implements KeyEncapsulation
{
    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private DerivationFunction kdf;
    private SecureRandom rnd;
    private RSAKeyParameters key;

    /**
     * Set up the RSA-KEM.
     *
     * @param kdf the key derivation function to be used.
     * @param rnd the random source for the session key.
     */
    public RSAKeyEncapsulation(
        DerivationFunction kdf,
        SecureRandom rnd)
    {
        this.kdf = kdf;
        this.rnd = rnd;
    }

    /**
     * Initialise the RSA-KEM.
     *
     * @param key the recipient's public (for encryption) or private (for decryption) key.
     */
    public void init(CipherParameters key)
        throws IllegalArgumentException
    {
        if (!(key instanceof RSAKeyParameters))
        {
            throw new IllegalArgumentException("RSA key required");
        }

        this.key = (RSAKeyParameters)key;
    }

    /**
     * Generate and encapsulate a random session key.
     *
     * @param out    the output buffer for the encapsulated key.
     * @param outOff the offset for the output buffer.
     * @param keyLen the length of the random session key.
     * @return the random session key.
     */
    public CipherParameters encrypt(byte[] out, int outOff, int keyLen)
        throws IllegalArgumentException
    {
        if (key.isPrivate())
        {
            throw new IllegalArgumentException("Public key required for encryption");
        }

        BigInteger n = key.getModulus();
        BigInteger e = key.getExponent();

        // Generate the ephemeral random and encode it    
        BigInteger r = BigIntegers.createRandomInRange(ZERO, n.subtract(ONE), rnd);

        // Encrypt the random and encode it     
        BigInteger c = r.modPow(e, n);
        byte[] C = BigIntegers.asUnsignedByteArray((n.bitLength() + 7) / 8, c);
        System.arraycopy(C, 0, out, outOff, C.length);

        return generateKey(n, r, keyLen);
    }

    /**
     * Generate and encapsulate a random session key.
     *
     * @param out    the output buffer for the encapsulated key.
     * @param keyLen the length of the random session key.
     * @return the random session key.
     */
    public CipherParameters encrypt(byte[] out, int keyLen)
    {
        return encrypt(out, 0, keyLen);
    }

    /**
     * Decrypt an encapsulated session key.
     *
     * @param in     the input buffer for the encapsulated key.
     * @param inOff  the offset for the input buffer.
     * @param inLen  the length of the encapsulated key.
     * @param keyLen the length of the session key.
     * @return the session key.
     */
    public CipherParameters decrypt(byte[] in, int inOff, int inLen, int keyLen)
        throws IllegalArgumentException
    {
        if (!key.isPrivate())
        {
            throw new IllegalArgumentException("Private key required for decryption");
        }

        BigInteger n = key.getModulus();
        BigInteger d = key.getExponent();

        // Decode the input
        byte[] C = new byte[inLen];
        System.arraycopy(in, inOff, C, 0, C.length);
        BigInteger c = new BigInteger(1, C);

        // Decrypt the ephemeral random and encode it
        BigInteger r = c.modPow(d, n);

        return generateKey(n, r, keyLen);
    }

    /**
     * Decrypt an encapsulated session key.
     *
     * @param in     the input buffer for the encapsulated key.
     * @param keyLen the length of the session key.
     * @return the session key.
     */
    public CipherParameters decrypt(byte[] in, int keyLen)
    {
        return decrypt(in, 0, in.length, keyLen);
    }

    protected KeyParameter generateKey(BigInteger n, BigInteger r, int keyLen)
    {
        byte[] R = BigIntegers.asUnsignedByteArray((n.bitLength() + 7) / 8, r);

        // Initialise the KDF
        kdf.init(new KDFParameters(R, null));

        // Generate the secret key
        byte[] K = new byte[keyLen];
        kdf.generateBytes(K, 0, K.length);

        return new KeyParameter(K);
    }
}
