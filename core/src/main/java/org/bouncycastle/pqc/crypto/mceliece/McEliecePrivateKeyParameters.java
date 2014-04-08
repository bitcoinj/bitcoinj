package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;


public class McEliecePrivateKeyParameters
    extends McElieceKeyParameters
{

    // the OID of the algorithm
    private String oid;

    // the length of the code
    private int n;

    // the dimension of the code, where <tt>k &gt;= n - mt</tt>
    private int k;

    // the underlying finite field
    private GF2mField field;

    // the irreducible Goppa polynomial
    private PolynomialGF2mSmallM goppaPoly;

    // a k x k random binary non-singular matrix
    private GF2Matrix sInv;

    // the permutation used to generate the systematic check matrix
    private Permutation p1;

    // the permutation used to compute the public generator matrix
    private Permutation p2;

    // the canonical check matrix of the code
    private GF2Matrix h;

    // the matrix used to compute square roots in <tt>(GF(2^m))^t</tt>
    private PolynomialGF2mSmallM[] qInv;

    /**
     * Constructor.
     *
     * @param oid
     * @param n         the length of the code
     * @param k         the dimension of the code
     * @param field     the field polynomial defining the finite field
     *                  <tt>GF(2<sup>m</sup>)</tt>
     * @param goppaPoly the irreducible Goppa polynomial
     * @param sInv      the matrix <tt>S<sup>-1</sup></tt>
     * @param p1        the permutation used to generate the systematic check
     *                  matrix
     * @param p2        the permutation used to compute the public generator
     *                  matrix
     * @param h         the canonical check matrix
     * @param qInv      the matrix used to compute square roots in
     *                  <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt>
     * @param params    McElieceParameters
     */
    public McEliecePrivateKeyParameters(String oid, int n, int k, GF2mField field,
                                        PolynomialGF2mSmallM goppaPoly, GF2Matrix sInv, Permutation p1,
                                        Permutation p2, GF2Matrix h, PolynomialGF2mSmallM[] qInv, McElieceParameters params)
    {
        super(true, params);
        this.oid = oid;
        this.k = k;
        this.n = n;
        this.field = field;
        this.goppaPoly = goppaPoly;
        this.sInv = sInv;
        this.p1 = p1;
        this.p2 = p2;
        this.h = h;
        this.qInv = qInv;
    }

    /**
     * Constructor (used by the {@link McElieceKeyFactory}).
     *
     * @param oid
     * @param n            the length of the code
     * @param k            the dimension of the code
     * @param encField     the encoded field polynomial defining the finite field
     *                     <tt>GF(2<sup>m</sup>)</tt>
     * @param encGoppaPoly the encoded irreducible Goppa polynomial
     * @param encSInv      the encoded matrix <tt>S<sup>-1</sup></tt>
     * @param encP1        the encoded permutation used to generate the systematic
     *                     check matrix
     * @param encP2        the encoded permutation used to compute the public
     *                     generator matrix
     * @param encH         the encoded canonical check matrix
     * @param encQInv      the encoded matrix used to compute square roots in
     *                     <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt>
     * @param params       McElieceParameters
     */
    public McEliecePrivateKeyParameters(String oid, int n, int k, byte[] encField,
                                        byte[] encGoppaPoly, byte[] encSInv, byte[] encP1, byte[] encP2,
                                        byte[] encH, byte[][] encQInv, McElieceParameters params)
    {
        super(true, params);
        this.oid = oid;
        this.n = n;
        this.k = k;
        field = new GF2mField(encField);
        goppaPoly = new PolynomialGF2mSmallM(field, encGoppaPoly);
        sInv = new GF2Matrix(encSInv);
        p1 = new Permutation(encP1);
        p2 = new Permutation(encP2);
        h = new GF2Matrix(encH);
        qInv = new PolynomialGF2mSmallM[encQInv.length];
        for (int i = 0; i < encQInv.length; i++)
        {
            qInv[i] = new PolynomialGF2mSmallM(field, encQInv[i]);
        }
    }

    /**
     * @return the length of the code
     */
    public int getN()
    {
        return n;
    }

    /**
     * @return the dimension of the code
     */
    public int getK()
    {
        return k;
    }

    /**
     * @return the finite field <tt>GF(2<sup>m</sup>)</tt>
     */
    public GF2mField getField()
    {
        return field;
    }

    /**
     * @return the irreducible Goppa polynomial
     */
    public PolynomialGF2mSmallM getGoppaPoly()
    {
        return goppaPoly;
    }

    /**
     * @return the k x k random binary non-singular matrix S^-1
     */
    public GF2Matrix getSInv()
    {
        return sInv;
    }

    /**
     * @return the permutation used to generate the systematic check matrix
     */
    public Permutation getP1()
    {
        return p1;
    }

    /**
     * @return the permutation used to compute the public generator matrix
     */
    public Permutation getP2()
    {
        return p2;
    }

    /**
     * @return the canonical check matrix H
     */
    public GF2Matrix getH()
    {
        return h;
    }

    /**
     * @return the matrix used to compute square roots in
     *         <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt>
     */
    public PolynomialGF2mSmallM[] getQInv()
    {
        return qInv;
    }

    public String getOIDString()
    {
        return oid;
    }

}
