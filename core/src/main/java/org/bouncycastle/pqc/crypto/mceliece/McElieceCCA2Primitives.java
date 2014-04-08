package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.GoppaCode;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import org.bouncycastle.pqc.math.linearalgebra.Vector;

/**
 * Core operations for the CCA-secure variants of McEliece.
 */
public final class McElieceCCA2Primitives
{

    /**
     * Default constructor (private).
     */
    private McElieceCCA2Primitives()
    {
    }

    /**
     * The McEliece encryption primitive.
     *
     * @param pubKey the public key
     * @param m      the message vector
     * @param z      the error vector
     * @return <tt>m*G + z</tt>
     */


    public static GF2Vector encryptionPrimitive(McElieceCCA2PublicKeyParameters pubKey,
                                                GF2Vector m, GF2Vector z)
    {

        GF2Matrix matrixG = pubKey.getMatrixG();
        Vector mG = matrixG.leftMultiplyLeftCompactForm(m);
        return (GF2Vector)mG.add(z);
    }

    /**
     * The McEliece decryption primitive.
     *
     * @param privKey the private key
     * @param c       the ciphertext vector <tt>c = m*G + z</tt>
     * @return the message vector <tt>m</tt> and the error vector <tt>z</tt>
     */
    public static GF2Vector[] decryptionPrimitive(
        McElieceCCA2PrivateKeyParameters privKey, GF2Vector c)
    {

        // obtain values from private key
        int k = privKey.getK();
        Permutation p = privKey.getP();
        GF2mField field = privKey.getField();
        PolynomialGF2mSmallM gp = privKey.getGoppaPoly();
        GF2Matrix h = privKey.getH();
        PolynomialGF2mSmallM[] q = privKey.getQInv();

        // compute inverse permutation P^-1
        Permutation pInv = p.computeInverse();

        // multiply c with permutation P^-1
        GF2Vector cPInv = (GF2Vector)c.multiply(pInv);

        // compute syndrome of cP^-1
        GF2Vector syndVec = (GF2Vector)h.rightMultiply(cPInv);

        // decode syndrome
        GF2Vector errors = GoppaCode.syndromeDecode(syndVec, field, gp, q);
        GF2Vector mG = (GF2Vector)cPInv.add(errors);

        // multiply codeword and error vector with P
        mG = (GF2Vector)mG.multiply(p);
        errors = (GF2Vector)errors.multiply(p);

        // extract plaintext vector (last k columns of mG)
        GF2Vector m = mG.extractRightVector(k);

        // return vectors
        return new GF2Vector[]{m, errors};
    }

}
