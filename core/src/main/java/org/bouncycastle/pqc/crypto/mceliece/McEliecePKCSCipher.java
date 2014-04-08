package org.bouncycastle.pqc.crypto.mceliece;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageEncryptor;
import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.GoppaCode;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import org.bouncycastle.pqc.math.linearalgebra.Vector;

/**
 * This class implements the McEliece Public Key cryptosystem (McEliecePKCS). It
 * was first described in R.J. McEliece, "A public key cryptosystem based on
 * algebraic coding theory", DSN progress report, 42-44:114-116, 1978. The
 * McEliecePKCS is the first cryptosystem which is based on error correcting
 * codes. The trapdoor for the McEliece cryptosystem using Goppa codes is the
 * knowledge of the Goppa polynomial used to generate the code.
 */
public class McEliecePKCSCipher
    implements MessageEncryptor
{

    /**
     * The OID of the algorithm.
     */
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.4.1";


    // the source of randomness
    private SecureRandom sr;

    // the McEliece main parameters
    private int n, k, t;

    // The maximum number of bytes the cipher can decrypt
    public int maxPlainTextSize;

    // The maximum number of bytes the cipher can encrypt
    public int cipherTextSize;

    McElieceKeyParameters key;


    public void init(boolean forSigning,
                     CipherParameters param)
    {

        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                ParametersWithRandom rParam = (ParametersWithRandom)param;

                this.sr = rParam.getRandom();
                this.key = (McEliecePublicKeyParameters)rParam.getParameters();
                this.initCipherEncrypt((McEliecePublicKeyParameters)key);

            }
            else
            {
                this.sr = new SecureRandom();
                this.key = (McEliecePublicKeyParameters)param;
                this.initCipherEncrypt((McEliecePublicKeyParameters)key);
            }
        }
        else
        {
            this.key = (McEliecePrivateKeyParameters)param;
            this.initCipherDecrypt((McEliecePrivateKeyParameters)key);
        }

    }


    /**
     * Return the key size of the given key object.
     *
     * @param key the McElieceKeyParameters object
     * @return the keysize of the given key object
     */

    public int getKeySize(McElieceKeyParameters key)
    {

        if (key instanceof McEliecePublicKeyParameters)
        {
            return ((McEliecePublicKeyParameters)key).getN();

        }
        if (key instanceof McEliecePrivateKeyParameters)
        {
            return ((McEliecePrivateKeyParameters)key).getN();
        }
        throw new IllegalArgumentException("unsupported type");

    }


    public void initCipherEncrypt(McEliecePublicKeyParameters pubKey)
    {
        this.sr = sr != null ? sr : new SecureRandom();
        n = pubKey.getN();
        k = pubKey.getK();
        t = pubKey.getT();
        cipherTextSize = n >> 3;
        maxPlainTextSize = (k >> 3);
    }


    public void initCipherDecrypt(McEliecePrivateKeyParameters privKey)
    {
        n = privKey.getN();
        k = privKey.getK();

        maxPlainTextSize = (k >> 3);
        cipherTextSize = n >> 3;
    }

    /**
     * Encrypt a plain text.
     *
     * @param input the plain text
     * @return the cipher text
     */
    public byte[] messageEncrypt(byte[] input)
    {
        GF2Vector m = computeMessageRepresentative(input);
        GF2Vector z = new GF2Vector(n, t, sr);

        GF2Matrix g = ((McEliecePublicKeyParameters)key).getG();
        Vector mG = g.leftMultiply(m);
        GF2Vector mGZ = (GF2Vector)mG.add(z);

        return mGZ.getEncoded();
    }

    private GF2Vector computeMessageRepresentative(byte[] input)
    {
        byte[] data = new byte[maxPlainTextSize + ((k & 0x07) != 0 ? 1 : 0)];
        System.arraycopy(input, 0, data, 0, input.length);
        data[input.length] = 0x01;
        return GF2Vector.OS2VP(k, data);
    }

    /**
     * Decrypt a cipher text.
     *
     * @param input the cipher text
     * @return the plain text
     * @throws Exception if the cipher text is invalid.
     */
    public byte[] messageDecrypt(byte[] input)
        throws Exception
    {
        GF2Vector vec = GF2Vector.OS2VP(n, input);
        McEliecePrivateKeyParameters privKey = (McEliecePrivateKeyParameters)key;
        GF2mField field = privKey.getField();
        PolynomialGF2mSmallM gp = privKey.getGoppaPoly();
        GF2Matrix sInv = privKey.getSInv();
        Permutation p1 = privKey.getP1();
        Permutation p2 = privKey.getP2();
        GF2Matrix h = privKey.getH();
        PolynomialGF2mSmallM[] qInv = privKey.getQInv();

        // compute permutation P = P1 * P2
        Permutation p = p1.rightMultiply(p2);

        // compute P^-1
        Permutation pInv = p.computeInverse();

        // compute c P^-1
        GF2Vector cPInv = (GF2Vector)vec.multiply(pInv);

        // compute syndrome of c P^-1
        GF2Vector syndrome = (GF2Vector)h.rightMultiply(cPInv);

        // decode syndrome
        GF2Vector z = GoppaCode.syndromeDecode(syndrome, field, gp, qInv);
        GF2Vector mSG = (GF2Vector)cPInv.add(z);

        // multiply codeword with P1 and error vector with P
        mSG = (GF2Vector)mSG.multiply(p1);
        z = (GF2Vector)z.multiply(p);

        // extract mS (last k columns of mSG)
        GF2Vector mS = mSG.extractRightVector(k);

        // compute plaintext vector
        GF2Vector mVec = (GF2Vector)sInv.leftMultiply(mS);

        // compute and return plaintext
        return computeMessage(mVec);
    }

    private byte[] computeMessage(GF2Vector mr)
        throws Exception
    {
        byte[] mrBytes = mr.getEncoded();
        // find first non-zero byte
        int index;
        for (index = mrBytes.length - 1; index >= 0 && mrBytes[index] == 0; index--)
        {
            ;
        }

        // check if padding byte is valid
        if (mrBytes[index] != 0x01)
        {
            throw new Exception("Bad Padding: invalid ciphertext");
        }

        // extract and return message
        byte[] mBytes = new byte[index];
        System.arraycopy(mrBytes, 0, mBytes, 0, index);
        return mBytes;
    }


}
