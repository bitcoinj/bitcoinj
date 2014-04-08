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
import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;

/**
 * This class implements the Kobara/Imai conversion of the McEliecePKCS. This is
 * a conversion of the McEliecePKCS which is CCA2-secure. For details, see D.
 * Engelbert, R. Overbeck, A. Schmidt, "A summary of the development of the
 * McEliece Cryptosystem", technical report.
 */
public class McElieceKobaraImaiCipher
    implements MessageEncryptor
{

    /**
     * The OID of the algorithm.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.2.3";

    private static final String DEFAULT_PRNG_NAME = "SHA1PRNG";

    /**
     * A predetermined public constant.
     */
    public static final byte[] PUBLIC_CONSTANT = "a predetermined public constant"
        .getBytes();


    private Digest messDigest;

    private SecureRandom sr;

    McElieceCCA2KeyParameters key;

    /**
     * The McEliece main parameters
     */
    private int n, k, t;


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
     */
    public int getKeySize(McElieceCCA2KeyParameters key)
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

        int c2Len = messDigest.getDigestSize();
        int c4Len = k >> 3;
        int c5Len = (IntegerFunctions.binomial(n, t).bitLength() - 1) >> 3;


        int mLen = c4Len + c5Len - c2Len - PUBLIC_CONSTANT.length;
        if (input.length > mLen)
        {
            mLen = input.length;
        }

        int c1Len = mLen + PUBLIC_CONSTANT.length;
        int c6Len = c1Len + c2Len - c4Len - c5Len;

        // compute (m||const)
        byte[] mConst = new byte[c1Len];
        System.arraycopy(input, 0, mConst, 0, input.length);
        System.arraycopy(PUBLIC_CONSTANT, 0, mConst, mLen,
            PUBLIC_CONSTANT.length);

        // generate random r of length c2Len bytes
        byte[] r = new byte[c2Len];
        sr.nextBytes(r);

        // get PRNG object
                // get PRNG object
        DigestRandomGenerator sr0 = new DigestRandomGenerator(new SHA1Digest());

        // seed PRNG with r'
        sr0.addSeedMaterial(r);

        // generate random sequence ...
        byte[] c1 = new byte[c1Len];
        sr0.nextBytes(c1);

        // ... and XOR with (m||const) to obtain c1
        for (int i = c1Len - 1; i >= 0; i--)
        {
            c1[i] ^= mConst[i];
        }

        // compute H(c1) ...
        byte[] c2 = new byte[messDigest.getDigestSize()];
        messDigest.update(c1, 0, c1.length);
        messDigest.doFinal(c2, 0);

        // ... and XOR with r
        for (int i = c2Len - 1; i >= 0; i--)
        {
            c2[i] ^= r[i];
        }

        // compute (c2||c1)
        byte[] c2c1 = ByteUtils.concatenate(c2, c1);

        // split (c2||c1) into (c6||c5||c4), where c4Len is k/8 bytes, c5Len is
        // floor[log(n|t)]/8 bytes, and c6Len is c1Len+c2Len-c4Len-c5Len (may be
        // 0).
        byte[] c6 = new byte[0];
        if (c6Len > 0)
        {
            c6 = new byte[c6Len];
            System.arraycopy(c2c1, 0, c6, 0, c6Len);
        }

        byte[] c5 = new byte[c5Len];
        System.arraycopy(c2c1, c6Len, c5, 0, c5Len);

        byte[] c4 = new byte[c4Len];
        System.arraycopy(c2c1, c6Len + c5Len, c4, 0, c4Len);

        // convert c4 to vector over GF(2)
        GF2Vector c4Vec = GF2Vector.OS2VP(k, c4);

        // convert c5 to error vector z
        GF2Vector z = Conversions.encode(n, t, c5);

        // compute encC4 = E(c4, z)
        byte[] encC4 = McElieceCCA2Primitives.encryptionPrimitive((McElieceCCA2PublicKeyParameters)key,
            c4Vec, z).getEncoded();

        // if c6Len > 0
        if (c6Len > 0)
        {
            // return (c6||encC4)
            return ByteUtils.concatenate(c6, encC4);
        }
        // else, return encC4
        return encC4;
    }


    public byte[] messageDecrypt(byte[] input)
        throws Exception
    {

        int nDiv8 = n >> 3;

        if (input.length < nDiv8)
        {
            throw new Exception("Bad Padding: Ciphertext too short.");
        }

        int c2Len = messDigest.getDigestSize();
        int c4Len = k >> 3;
        int c6Len = input.length - nDiv8;

        // split cipher text (c6||encC4), where c6 may be empty
        byte[] c6, encC4;
        if (c6Len > 0)
        {
            byte[][] c6EncC4 = ByteUtils.split(input, c6Len);
            c6 = c6EncC4[0];
            encC4 = c6EncC4[1];
        }
        else
        {
            c6 = new byte[0];
            encC4 = input;
        }

        // convert encC4 into vector over GF(2)
        GF2Vector encC4Vec = GF2Vector.OS2VP(n, encC4);

        // decrypt encC4Vec to obtain c4 and error vector z
        GF2Vector[] c4z = McElieceCCA2Primitives.decryptionPrimitive((McElieceCCA2PrivateKeyParameters)key,
            encC4Vec);
        byte[] c4 = c4z[0].getEncoded();
        GF2Vector z = c4z[1];

        // if length of c4 is greater than c4Len (because of padding) ...
        if (c4.length > c4Len)
        {
            // ... truncate the padding bytes
            c4 = ByteUtils.subArray(c4, 0, c4Len);
        }

        // compute c5 = Conv^-1(z)
        byte[] c5 = Conversions.decode(n, t, z);

        // compute (c6||c5||c4)
        byte[] c6c5c4 = ByteUtils.concatenate(c6, c5);
        c6c5c4 = ByteUtils.concatenate(c6c5c4, c4);

        // split (c6||c5||c4) into (c2||c1), where c2Len = mdLen and c1Len =
        // input.length-c2Len bytes.
        int c1Len = c6c5c4.length - c2Len;
        byte[][] c2c1 = ByteUtils.split(c6c5c4, c2Len);
        byte[] c2 = c2c1[0];
        byte[] c1 = c2c1[1];

        // compute H(c1) ...
        byte[] rPrime = new byte[messDigest.getDigestSize()];
        messDigest.update(c1, 0, c1.length);
        messDigest.doFinal(rPrime, 0);

        // ... and XOR with c2 to obtain r'
        for (int i = c2Len - 1; i >= 0; i--)
        {
            rPrime[i] ^= c2[i];
        }

        // get PRNG object
        DigestRandomGenerator sr0 = new DigestRandomGenerator(new SHA1Digest());

        // seed PRNG with r'
        sr0.addSeedMaterial(rPrime);

        // generate random sequence R(r') ...
        byte[] mConstPrime = new byte[c1Len];
        sr0.nextBytes(mConstPrime);

        // ... and XOR with c1 to obtain (m||const')
        for (int i = c1Len - 1; i >= 0; i--)
        {
            mConstPrime[i] ^= c1[i];
        }

        if (mConstPrime.length < c1Len)
        {
            throw new Exception("Bad Padding: invalid ciphertext");
        }

        byte[][] temp = ByteUtils.split(mConstPrime, c1Len
            - PUBLIC_CONSTANT.length);
        byte[] mr = temp[0];
        byte[] constPrime = temp[1];

        if (!ByteUtils.equals(constPrime, PUBLIC_CONSTANT))
        {
            throw new Exception("Bad Padding: invalid ciphertext");
        }

        return mr;
    }


}
