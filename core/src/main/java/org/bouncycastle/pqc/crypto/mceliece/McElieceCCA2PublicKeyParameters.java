package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

/**
 *
 *
 *
 */
public class McElieceCCA2PublicKeyParameters
    extends McElieceCCA2KeyParameters
{

    // the OID of the algorithm
    private String oid;

    // the length of the code
    private int n;

    // the error correction capability of the code
    private int t;

    // the generator matrix
    private GF2Matrix matrixG;

    /**
     * Constructor.
     *
     * @param n      length of the code
     * @param t      error correction capability
     * @param matrix generator matrix
     * @param params McElieceCCA2Parameters
     */
    public McElieceCCA2PublicKeyParameters(String oid, int n, int t, GF2Matrix matrix, McElieceCCA2Parameters params)
    {
        super(false, params);
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.matrixG = new GF2Matrix(matrix);
    }

    /**
     * Constructor (used by {@link McElieceKeyFactory}).
     *
     * @param n         length of the code
     * @param t         error correction capability of the code
     * @param encMatrix encoded generator matrix
     * @param params    McElieceCCA2Parameters
     */
    public McElieceCCA2PublicKeyParameters(String oid, int n, int t, byte[] encMatrix, McElieceCCA2Parameters params)
    {
        super(false, params);
        this.oid = oid;
        this.n = n;
        this.t = t;
        this.matrixG = new GF2Matrix(encMatrix);
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
    public GF2Matrix getMatrixG()
    {
        return matrixG;
    }

    /**
     * @return the dimension of the code
     */
    public int getK()
    {
        return matrixG.getNumRows();
    }

    public String getOIDString()
    {
        return oid;

    }
}
