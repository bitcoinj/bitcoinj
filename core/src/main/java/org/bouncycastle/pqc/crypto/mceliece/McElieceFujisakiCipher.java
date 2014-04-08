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
 * This class implements the Fujisaki/Okamoto conversion of the McEliecePKCS.
 * Fujisaki and Okamoto propose hybrid encryption that merges a symmetric
 * encryption scheme which is secure in the find-guess model with an asymmetric
 * one-way encryption scheme which is sufficiently probabilistic to obtain a
 * public key cryptosystem which is CCA2-secure. For details, see D. Engelbert,
 * R. Overbeck, A. Schmidt, "A summary of the development of the McEliece
 * Cryptosystem", technical report.
 */
public class McElieceFujisakiCipher
    implements MessageEncryptor
{


    /**
     * The OID of the algorithm.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2.1";

    private static final String DEFAULT_PRNG_NAME = "SHA1PRNG";

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


    private void initCipherEncrypt(McElieceCCA2PublicKeyParameters pubKey)
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
        t = privKey.getT();
    }


    public byte[] messageEncrypt(byte[] input)
        throws Exception
    {

        // generate random vector r of length k bits
        GF2Vector r = new GF2Vector(k, sr);

        // convert r to byte array
        byte[] rBytes = r.getEncoded();

        // compute (r||input)
        byte[] rm = ByteUtils.concatenate(rBytes, input);

        // compute H(r||input)
        messDigest.update(rm, 0, rm.length);
        byte[] hrm = new byte[messDigest.getDigestSize()];
        messDigest.doFinal(hrm, 0);

        // convert H(r||input) to error vector z
        GF2Vector z = Conversions.encode(n, t, hrm);

        // compute c1 = E(r, z)
        byte[] c1 = McElieceCCA2Primitives.encryptionPrimitive((McElieceCCA2PublicKeyParameters)key, r, z)
            .getEncoded();

        // get PRNG object
        DigestRandomGenerator sr0 = new DigestRandomGenerator(new SHA1Digest());

        // seed PRNG with r'
        sr0.addSeedMaterial(rBytes);

        // generate random c2
        byte[] c2 = new byte[input.length];
        sr0.nextBytes(c2);

        // XOR with input
        for (int i = 0; i < input.length; i++)
        {
            c2[i] ^= input[i];
        }

        // return (c1||c2)
        return ByteUtils.concatenate(c1, c2);
    }

    public byte[] messageDecrypt(byte[] input)
        throws Exception
    {

        int c1Len = (n + 7) >> 3;
        int c2Len = input.length - c1Len;

        // split ciphertext (c1||c2)
        byte[][] c1c2 = ByteUtils.split(input, c1Len);
        byte[] c1 = c1c2[0];
        byte[] c2 = c1c2[1];

        // decrypt c1 ...
        GF2Vector hrmVec = GF2Vector.OS2VP(n, c1);
        GF2Vector[] decC1 = McElieceCCA2Primitives.decryptionPrimitive((McElieceCCA2PrivateKeyParameters)key,
            hrmVec);
        byte[] rBytes = decC1[0].getEncoded();
        // ... and obtain error vector z
        GF2Vector z = decC1[1];

        // get PRNG object
        DigestRandomGenerator sr0 = new DigestRandomGenerator(new SHA1Digest());

        // seed PRNG with r'
        sr0.addSeedMaterial(rBytes);

        // generate random sequence
        byte[] mBytes = new byte[c2Len];
        sr0.nextBytes(mBytes);

        // XOR with c2 to obtain m
        for (int i = 0; i < c2Len; i++)
        {
            mBytes[i] ^= c2[i];
        }

        // compute H(r||m)
        byte[] rmBytes = ByteUtils.concatenate(rBytes, mBytes);
        byte[] hrm = new byte[messDigest.getDigestSize()];
        messDigest.update(rmBytes, 0, rmBytes.length);
        messDigest.doFinal(hrm, 0);


        // compute Conv(H(r||m))
        hrmVec = Conversions.encode(n, t, hrm);

        // check that Conv(H(m||r)) = z
        if (!hrmVec.equals(z))
        {

            throw new Exception("Bad Padding: invalid ciphertext");

        }

        // return plaintext m
        return mBytes;
    }


}
