package org.bouncycastle.pqc.crypto.rainbow;

public class RainbowPrivateKeyParameters
    extends RainbowKeyParameters
{
    /**
     * Constructor
     *
     * @param A1inv  the inverse of A1(the matrix part of the affine linear map L1)
     *               (n-v1 x n-v1 matrix)
     * @param b1     translation vector, part of the linear affine map L1
     * @param A2inv  the inverse of A2(the matrix part of the affine linear map L2)
 *               (n x n matrix)
     * @param b2     translation vector, part of the linear affine map L2
     * @param vi     the number of Vinegar-variables per layer
     * @param layers the polynomials with their coefficients of private map F
     */
    public RainbowPrivateKeyParameters(short[][] A1inv, short[] b1,
                                       short[][] A2inv, short[] b2, int[] vi, Layer[] layers)
    {
        super(true, vi[vi.length - 1] - vi[0]);

        this.A1inv = A1inv;
        this.b1 = b1;
        this.A2inv = A2inv;
        this.b2 = b2;
        this.vi = vi;
        this.layers = layers;
    }

    /*
      * invertible affine linear map L1
      */
    // the inverse of A1, (n-v1 x n-v1 matrix)
    private short[][] A1inv;

    // translation vector of L1
    private short[] b1;

    /*
      * invertible affine linear map L2
      */
    // the inverse of A2, (n x n matrix)
    private short[][] A2inv;

    // translation vector of L2
    private short[] b2;

    /*
      * components of F
      */
    // the number of Vinegar-variables per layer.
    private int[] vi;

    // contains the polynomials with their coefficients of private map F
    private Layer[] layers;

    /**
     * Getter for the translation part of the private quadratic map L1.
     *
     * @return b1 the translation part of L1
     */
    public short[] getB1()
    {
        return this.b1;
    }

    /**
     * Getter for the inverse matrix of A1.
     *
     * @return the A1inv inverse
     */
    public short[][] getInvA1()
    {
        return this.A1inv;
    }

    /**
     * Getter for the translation part of the private quadratic map L2.
     *
     * @return b2 the translation part of L2
     */
    public short[] getB2()
    {
        return this.b2;
    }

    /**
     * Getter for the inverse matrix of A2
     *
     * @return the A2inv
     */
    public short[][] getInvA2()
    {
        return this.A2inv;
    }

    /**
     * Returns the layers contained in the private key
     *
     * @return layers
     */
    public Layer[] getLayers()
    {
        return this.layers;
    }

    /**
     * /** Returns the array of vi-s
     *
     * @return the vi
     */
    public int[] getVi()
    {
        return vi;
    }
}
