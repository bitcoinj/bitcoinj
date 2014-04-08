package org.bouncycastle.pqc.crypto.mceliece;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.prng.DigestRandomGenerator;
import org.bouncycastle.pqc.crypto.MessageEncryptor;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector;

/**
 * This class implements the Pointcheval conversion of the McEliecePKCS.
 * Pointcheval presents a generic technique to make a CCA2-secure cryptosystem
 * from any partially trapdoor one-way function in the random oracle model. For
 * details, see D. Engelbert, R. Overbeck, A. Schmidt, "A summary of the
 * development of the McEliece Cryptosystem", technical report.
 */
public class McEliecePointchevalCipher
    implements MessageEncryptor
{


    /**
     * The OID of the algorithm.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2.2";

    private Digest messDigest;

    private SecureRandom sr;

    /**
     * The McEliece main parameters
     */
    private int n, k, t;

    McElieceCCA2KeyParameters key;

    public void init(boolean forSigning,
                     CipherParameters param)
    {

        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom rParam = (ParametersWithRandom)param;

                this.sr = rParam.getRandom();
                this.key = (McElieceCCA2PublicKeyParameters)rParam.getParameters();
                this.initCipherEncrypt((McElieceCCA2PublicKeyParameters)key);

            }
            else
            {
                this.sr = new SecureRandom();
                this.key = (McElieceCCA2PublicKeyParameters)param;
                this.initCipherEncrypt((McElieceCCA2PublicKeyParameters)key);
            }
        }
        else
        {
            this.key = (McElieceCCA2PrivateKeyParameters)param;
            this.initCipherDecrypt((McElieceCCA2PrivateKeyParameters)key);
        }

    }

    /**
     * Return the key size of the given key object.
     *
     * @param key the McElieceCCA2KeyParameters object
     * @return the key size of the given key object
     * @throws IllegalArgumentException if the key is invalid
     */
    public int getKeySize(McElieceCCA2KeyParameters key)
        throws IllegalArgumentException
    {

        if (key instanceof McElieceCCA2PublicKeyParameters)
        {
            return ((McElieceCCA2PublicKeyParameters)key).getN();

        }
        if (key instanceof McElieceCCA2PrivateKeyParameters)
        {
            return ((McElieceCCA2PrivateKeyParameters)key).getN();
        }
        throw new IllegalArgumentException("unsupported type");

    }


    protected int decryptOutputSize(int inLen)
    {
        return 0;
    }

    protected int encryptOutputSize(int inLen)
    {
        return 0;
    }


    public void initCipherEncrypt(McElieceCCA2PublicKeyParameters pubKey)
    {
        this.sr = sr != null ? sr : new SecureRandom();
        this.messDigest = pubKey.getParameters().getDigest();
        n = pubKey.getN();
        k = pubKey.getK();
        t = pubKey.getT();
    }

    public void initCipherDecrypt(McElieceCCA2PrivateKeyParameters privKey)
    {
        this.messDigest = privKey.getParameters().getDigest();
        n = privKey.getN();
        k = privKey.getK();
        t = privKey.getT();
    }

    public byte[] messageEncrypt(byte[] input)
        throws Exception
    {

        int kDiv8 = k >> 3;

        // generate random r of length k div 8 bytes
        byte[] r = new byte[kDiv8];
        sr.nextBytes(r);

        // generate random vector r' of length k bits
        GF2Vector rPrime = new GF2Vector(k, sr);

        // convert r' to byte array
        byte[] rPrimeBytes = rPrime.getEncoded();

        // compute (input||r)
        byte[] mr = ByteUtils.concatenate(input, r);

        // compute H(input||r)
        messDigest.update(mr, 0, mr.length);
        byte[] hmr = new byte[messDigest.getDigestSize()];
        messDigest.doFinal(hmr, 0);


        // convert H(input||r) to error vector z
        GF2Vector z = Conversions.encode(n, t, hmr);

        // compute c1 = E(rPrime, z)
        byte[] c1 = McElieceCCA2Primitives.encryptionPrimitive((McElieceCCA2PublicKeyParameters)key, rPrime,
            z).getEncoded();

        // get PRNG object
        DigestRandomGenerator sr0 = new DigestRandomGenerator(new SHA1Digest());

        // seed PRNG with r'
        sr0.addSeedMaterial(rPrimeBytes);

        // generate random c2
        byte[] c2 = new byte[input.length + kDiv8];
        sr0.nextBytes(c2);

        // XOR with input
        for (int i = 0; i < input.length; i++)
        {
            c2[i] ^= input[i];
        }
        // XOR with r
        for (int i = 0; i < kDiv8; i++)
        {
            c2[input.length + i] ^= r[i];
        }

        // return (c1||c2)
        return ByteUtils.concatenate(c1, c2);
    }

    public byte[] messageDecrypt(byte[] input)
        throws Exception
    {

        int c1Len = (n + 7) >> 3;
        int c2Len = input.length - c1Len;

        // split cipher text (c1||c2)
        byte[][] c1c2 = ByteUtils.split(input, c1Len);
        byte[] c1 = c1c2[0];
        byte[] c2 = c1c2[1];

        // decrypt c1 ...
        GF2Vector c1Vec = GF2Vector.OS2VP(n, c1);
        GF2Vector[] c1Dec = McElieceCCA2Primitives.decryptionPrimitive((McElieceCCA2PrivateKeyParameters)key,
            c1Vec);
        byte[] rPrimeBytes = c1Dec[0].getEncoded();
        // ... and obtain error vector z
        GF2Vector z = c1Dec[1];

        // get PRNG object
        DigestRandomGenerator sr0 = new DigestRandomGenerator(new SHA1Digest());

        // seed PRNG with r'
        sr0.addSeedMaterial(rPrimeBytes);

        // generate random sequence
        byte[] mrBytes = new byte[c2Len];
        sr0.nextBytes(mrBytes);

        // XOR with c2 to obtain (m||r)
        for (int i = 0; i < c2Len; i++)
        {
            mrBytes[i] ^= c2[i];
        }

        // compute H(m||r)
        messDigest.update(mrBytes, 0, mrBytes.length);
        byte[] hmr = new byte[messDigest.getDigestSize()];
        messDigest.doFinal(hmr, 0);

        // compute Conv(H(m||r))
        c1Vec = Conversions.encode(n, t, hmr);

        // check that Conv(H(m||r)) = z
        if (!c1Vec.equals(z))
        {
            throw new Exception("Bad Padding: Invalid ciphertext.");
        }

        // split (m||r) to obtain m
        int kDiv8 = k >> 3;
        byte[][] mr = ByteUtils.split(mrBytes, c2Len - kDiv8);

        // return plain text m
        return mr[0];
    }


}
