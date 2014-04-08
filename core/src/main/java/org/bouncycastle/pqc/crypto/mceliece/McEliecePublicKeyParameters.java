package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;


public class McEliecePublicKeyParameters
    extends McElieceKeyParameters
{

    // the OID of the algorithm
    private String oid;

    // the length of the code
    private int n;

    // the error correction capability of the code
    private int t;

    // the generator matrix
    private GF2Matrix g;

    /**
     * Constructor (used by {@link McElieceKeyFactory}).
     *
     * @param oid
     * @param n      the length of the code
     * @param t      the error correction capability of the code
     * @param g      the generator matrix
     * @param params McElieceParameters
     */
    public McEliecePublicKeyParameters(String oid, int n, int t, GF2Matrix g, McElieceParameters params)
    {
        super(false, params);
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.g = new GF2Matrix(g);
    }

    /**
     * Constructor (used by {@link McElieceKeyFactory}).
     *
     * @param oid
     * @param n      the length of the code
     * @param t      the error correction capability of the code
     * @param encG   the encoded generator matrix
     * @param params McElieceParameters
     */
    public McEliecePublicKeyParameters(String oid, int t, int n, byte[] encG, McElieceParameters params)
    {
        super(false, params);
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.g = new GF2Matrix(encG);
    }

    /**
     * @return the length of the code
     */
    public int getN()
    {
        return n;
    }

    /**
     * @return the error correction capability of the code
     */
    public int getT()
    {
        return t;
    }

    /**
     * @return the generator matrix
     */
    public GF2Matrix getG()
    {
        return g;
    }

    public String getOIDString()
    {
        return oid;

    }

    /**
     * @return the dimension of the code
     */
    public int getK()
    {
        return g.getNumRows();
    }

}
