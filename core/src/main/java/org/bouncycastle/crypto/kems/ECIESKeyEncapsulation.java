package org.bouncycastle.crypto.kems;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.KeyEncapsulation;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * The ECIES Key Encapsulation Mechanism (ECIES-KEM) from ISO 18033-2.
 */
public class ECIESKeyEncapsulation
    implements KeyEncapsulation
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private DerivationFunction kdf;
    private SecureRandom rnd;
    private ECKeyParameters key;
    private boolean CofactorMode;
    private boolean OldCofactorMode;
    private boolean SingleHashMode;

    /**
     * Set up the ECIES-KEM.
     *
     * @param kdf the key derivation function to be used.
     * @param rnd the random source for the session key.
     */
    public ECIESKeyEncapsulation(
        DerivationFunction kdf,
        SecureRandom rnd)
    {
        this.kdf = kdf;
        this.rnd = rnd;
        this.CofactorMode = false;
        this.OldCofactorMode = false;
        this.SingleHashMode = false;
    }

    /**
     * Set up the ECIES-KEM.
     *
     * @param kdf             the key derivation function to be used.
     * @param rnd             the random source for the session key.
     * @param cofactorMode    true to use the new cofactor ECDH.
     * @param oldCofactorMode true to use the old cofactor ECDH.
     * @param singleHashMode  true to use single hash mode.
     */
    public ECIESKeyEncapsulation(
        DerivationFunction kdf,
        SecureRandom rnd,
        boolean cofactorMode,
        boolean oldCofactorMode,
        boolean singleHashMode)
    {
        this.kdf = kdf;
        this.rnd = rnd;

        // If both cofactorMode and oldCofactorMode are set to true
        // then the implementation will use the new cofactor ECDH 
        this.CofactorMode = cofactorMode;
        this.OldCofactorMode = oldCofactorMode;
        this.SingleHashMode = singleHashMode;
    }

    /**
     * Initialise the ECIES-KEM.
     *
     * @param key the recipient's public (for encryption) or private (for decryption) key.
     */
    public void init(CipherParameters key)
        throws IllegalArgumentException
    {
        if (!(key instanceof ECKeyParameters))
        {
            throw new IllegalArgumentException("EC key required");
        }
        else
        {
            this.key = (ECKeyParameters)key;
        }
    }

    /**
     * Generate and encapsulate a random session key.
     *
     * @param out    the output buffer for the encapsulated key.
     * @param outOff the offset for the output buffer.
     * @param keyLen the length of the session key.
     * @return the random session key.
     */
    public CipherParameters encrypt(byte[] out, int outOff, int keyLen)
        throws IllegalArgumentException
    {
        if (!(key instanceof ECPublicKeyParameters))
        {
            throw new IllegalArgumentException("Public key required for encryption");
        }

        ECPublicKeyParameters ecPubKey = (ECPublicKeyParameters)key;
        ECDomainParameters ecParams = ecPubKey.getParameters();
        ECCurve curve = ecParams.getCurve();
        BigInteger n = ecParams.getN();
        BigInteger h = ecParams.getH();

        // Generate the ephemeral key pair    
        BigInteger r = BigIntegers.createRandomInRange(ONE, n, rnd);

        // Compute the static-ephemeral key agreement
        BigInteger rPrime = CofactorMode ? r.multiply(h).mod(n) : r;

        ECMultiplier basePointMultiplier = createBasePointMultiplier();

        ECPoint[] ghTilde = new ECPoint[]{ 
            basePointMultiplier.multiply(ecParams.getG(), r),
            ecPubKey.getQ().multiply(rPrime)
        };

        // NOTE: More efficient than normalizing each individually
        curve.normalizeAll(ghTilde);

        ECPoint gTilde = ghTilde[0], hTilde = ghTilde[1];

        // Encode the ephemeral public key
        byte[] C = gTilde.getEncoded();
        System.arraycopy(C, 0, out, outOff, C.length);

        // Encode the shared secret value
        byte[] PEH = hTilde.getAffineXCoord().getEncoded();

        // Initialise the KDF
        byte[] kdfInput = SingleHashMode ? Arrays.concatenate(C, PEH) : PEH;
        kdf.init(new KDFParameters(kdfInput, null));

        // Generate the secret key
        byte[] K = new byte[keyLen];
        kdf.generateBytes(K, 0, K.length);

        // Return the ciphertext
        return new KeyParameter(K);
    }

    /**
     * Generate and encapsulate a random session key.
     *
     * @param out    the output buffer for the encapsulated key.
     * @param keyLen the length of the session key.
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
        if (!(key instanceof ECPrivateKeyParameters))
        {
            throw new IllegalArgumentException("Private key required for encryption");
        }

        ECPrivateKeyParameters ecPrivKey = (ECPrivateKeyParameters)key;
        ECDomainParameters ecParams = ecPrivKey.getParameters();
        ECCurve curve = ecParams.getCurve();
        BigInteger n = ecParams.getN();
        BigInteger h = ecParams.getH();

        // Decode the ephemeral public key
        byte[] C = new byte[inLen];
        System.arraycopy(in, inOff, C, 0, inLen);

        // NOTE: Decoded points are already normalized (i.e in affine form)
        ECPoint gTilde = curve.decodePoint(C);

        // Compute the static-ephemeral key agreement
        ECPoint gHat = gTilde;
        if ((CofactorMode) || (OldCofactorMode))
        {
            gHat = gHat.multiply(h);
        }

        BigInteger xHat = ecPrivKey.getD();
        if (CofactorMode)
        {
            xHat = xHat.multiply(h.modInverse(n)).mod(n);
        }

        ECPoint hTilde = gHat.multiply(xHat).normalize();

        // Encode the shared secret value
        byte[] PEH = hTilde.getAffineXCoord().getEncoded();

        // Initialise the KDF
        byte[] kdfInput = SingleHashMode ? Arrays.concatenate(C, PEH) : PEH;
        kdf.init(new KDFParameters(kdfInput, null));

        // Generate the secret key
        byte[] K = new byte[keyLen];
        kdf.generateBytes(K, 0, K.length);

        return new KeyParameter(K);
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

    protected ECMultiplier createBasePointMultiplier()
    {
        return new FixedPointCombMultiplier();
    }
}
