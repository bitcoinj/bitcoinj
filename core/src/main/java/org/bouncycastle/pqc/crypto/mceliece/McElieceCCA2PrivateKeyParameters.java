package org.bouncycastle.pqc.crypto.mceliece;


import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;

/**
 *
 *
 *
 */
public class McElieceCCA2PrivateKeyParameters
    extends McElieceCCA2KeyParameters
{

    // the OID of the algorithm
    private String oid;

    // the length of the code
    private int n;

    // the dimension of the code
    private int k;

    // the finte field GF(2^m)
    private GF2mField field;

    // the irreducible Goppa polynomial
    private PolynomialGF2mSmallM goppaPoly;

    // the permutation
    private Permutation p;

    // the canonical check matrix
    private GF2Matrix h;

    // the matrix used to compute square roots in (GF(2^m))^t
    private PolynomialGF2mSmallM[] qInv;

    /**
     * Constructor.
     *
     * @param n      the length of the code
     * @param k      the dimension of the code
     * @param field  the finite field <tt>GF(2<sup>m</sup>)</tt>
     * @param gp     the irreducible Goppa polynomial
     * @param p      the permutation
     * @param h      the canonical check matrix
     * @param qInv   the matrix used to compute square roots in
     *               <tt>(GF(2^m))^t</tt>
     * @param params McElieceCCA2Parameters
     */
    public McElieceCCA2PrivateKeyParameters(String oid, int n, int k, GF2mField field,
                                            PolynomialGF2mSmallM gp, Permutation p, GF2Matrix h,
                                            PolynomialGF2mSmallM[] qInv, McElieceCCA2Parameters params)
    {
        super(true, params);
        this.oid = oid;
        this.n = n;
        this.k = k;
        this.field = field;
        this.goppaPoly = gp;
        this.p = p;
        this.h = h;
        this.qInv = qInv;
    }

    /**
     * Constructor used by the {@link McElieceKeyFactory}.
     *
     * @param n            the length of the code
     * @param k            the dimension of the code
     * @param encFieldPoly the encoded field polynomial defining the finite field
     *                     <tt>GF(2<sup>m</sup>)</tt>
     * @param encGoppaPoly the encoded irreducible Goppa polynomial
     * @param encP         the encoded permutation
     * @param encH         the encoded canonical check matrix
     * @param encQInv      the encoded matrix used to compute square roots in
     *                     <tt>(GF(2^m))^t</tt>
     * @param params       McElieceCCA2Parameters
     */
    public McElieceCCA2PrivateKeyParameters(String oid, int n, int k, byte[] encFieldPoly,
                                            byte[] encGoppaPoly, byte[] encP, byte[] encH, byte[][] encQInv, McElieceCCA2Parameters params)
    {
        super(true, params);
        this.oid = oid;
        this.n = n;
        this.k = k;
        field = new GF2mField(encFieldPoly);
        goppaPoly = new PolynomialGF2mSmallM(field, encGoppaPoly);
        p = new Permutation(encP);
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
     * @return the degree of the Goppa polynomial (error correcting capability)
     */
    public int getT()
    {
        return goppaPoly.getDegree();
    }

    /**
     * @return the finite field
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
     * @return the permutation P
     */
    public Permutation getP()
    {
        return p;
    }

    /**
     * @return the canonical check matrix H
     */
    public GF2Matrix getH()
    {
        return h;
    }

    /**
     * @return the matrix used to compute square roots in <tt>(GF(2^m))^t</tt>
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
