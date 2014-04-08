package org.bouncycastle.pqc.math.linearalgebra;

import java.security.SecureRandom;

/**
 * This class describes decoding operations of an irreducible binary Goppa code.
 * A check matrix H of the Goppa code and an irreducible Goppa polynomial are
 * used the operations are worked over a finite field GF(2^m)
 *
 * @see GF2mField
 * @see PolynomialGF2mSmallM
 */
public final class GoppaCode
{

    /**
     * Default constructor (private).
     */
    private GoppaCode()
    {
        // empty
    }

    /**
     * This class is a container for two instances of {@link GF2Matrix} and one
     * instance of {@link Permutation}. It is used to hold the systematic form
     * <tt>S*H*P = (Id|M)</tt> of the check matrix <tt>H</tt> as returned by
     * {@link GoppaCode#computeSystematicForm(GF2Matrix, SecureRandom)}.
     *
     * @see GF2Matrix
     * @see Permutation
     */
    public static class MaMaPe
    {

        private GF2Matrix s, h;

        private Permutation p;

        /**
         * Construct a new {@link MaMaPe} container with the given parameters.
         *
         * @param s the first matrix
         * @param h the second matrix
         * @param p the permutation
         */
        public MaMaPe(GF2Matrix s, GF2Matrix h, Permutation p)
        {
            this.s = s;
            this.h = h;
            this.p = p;
        }

        /**
         * @return the first matrix
         */
        public GF2Matrix getFirstMatrix()
        {
            return s;
        }

        /**
         * @return the second matrix
         */
        public GF2Matrix getSecondMatrix()
        {
            return h;
        }

        /**
         * @return the permutation
         */
        public Permutation getPermutation()
        {
            return p;
        }
    }

    /**
     * This class is a container for an instance of {@link GF2Matrix} and one
     * int[]. It is used to hold a generator matrix and the set of indices such
     * that the submatrix of the generator matrix consisting of the specified
     * columns is the identity.
     *
     * @see GF2Matrix
     * @see Permutation
     */
    public static class MatrixSet
    {

        private GF2Matrix g;

        private int[] setJ;

        /**
         * Construct a new {@link MatrixSet} container with the given
         * parameters.
         *
         * @param g    the generator matrix
         * @param setJ the set of indices such that the submatrix of the
         *             generator matrix consisting of the specified columns
         *             is the identity
         */
        public MatrixSet(GF2Matrix g, int[] setJ)
        {
            this.g = g;
            this.setJ = setJ;
        }

        /**
         * @return the generator matrix
         */
        public GF2Matrix getG()
        {
            return g;
        }

        /**
         * @return the set of indices such that the submatrix of the generator
         *         matrix consisting of the specified columns is the identity
         */
        public int[] getSetJ()
        {
            return setJ;
        }
    }

    /**
     * Construct the check matrix of a Goppa code in canonical form from the
     * irreducible Goppa polynomial over the finite field
     * <tt>GF(2<sup>m</sup>)</tt>.
     *
     * @param field the finite field
     * @param gp    the irreducible Goppa polynomial
     */
    public static GF2Matrix createCanonicalCheckMatrix(GF2mField field,
                                                       PolynomialGF2mSmallM gp)
    {
        int m = field.getDegree();
        int n = 1 << m;
        int t = gp.getDegree();

        /* create matrix H over GF(2^m) */

        int[][] hArray = new int[t][n];

        // create matrix YZ
        int[][] yz = new int[t][n];
        for (int j = 0; j < n; j++)
        {
            // here j is used as index and as element of field GF(2^m)
            yz[0][j] = field.inverse(gp.evaluateAt(j));
        }

        for (int i = 1; i < t; i++)
        {
            for (int j = 0; j < n; j++)
            {
                // here j is used as index and as element of field GF(2^m)
                yz[i][j] = field.mult(yz[i - 1][j], j);
            }
        }

        // create matrix H = XYZ
        for (int i = 0; i < t; i++)
        {
            for (int j = 0; j < n; j++)
            {
                for (int k = 0; k <= i; k++)
                {
                    hArray[i][j] = field.add(hArray[i][j], field.mult(yz[k][j],
                        gp.getCoefficient(t + k - i)));
                }
            }
        }

        /* convert to matrix over GF(2) */

        int[][] result = new int[t * m][(n + 31) >>> 5];

        for (int j = 0; j < n; j++)
        {
            int q = j >>> 5;
            int r = 1 << (j & 0x1f);
            for (int i = 0; i < t; i++)
            {
                int e = hArray[i][j];
                for (int u = 0; u < m; u++)
                {
                    int b = (e >>> u) & 1;
                    if (b != 0)
                    {
                        int ind = (i + 1) * m - u - 1;
                        result[ind][q] ^= r;
                    }
                }
            }
        }

        return new GF2Matrix(n, result);
    }

    /**
     * Given a check matrix <tt>H</tt>, compute matrices <tt>S</tt>,
     * <tt>M</tt>, and a random permutation <tt>P</tt> such that
     * <tt>S*H*P = (Id|M)</tt>. Return <tt>S^-1</tt>, <tt>M</tt>, and
     * <tt>P</tt> as {@link MaMaPe}. The matrix <tt>(Id | M)</tt> is called
     * the systematic form of H.
     *
     * @param h  the check matrix
     * @param sr a source of randomness
     * @return the tuple <tt>(S^-1, M, P)</tt>
     */
    public static MaMaPe computeSystematicForm(GF2Matrix h, SecureRandom sr)
    {
        int n = h.getNumColumns();
        GF2Matrix hp, sInv;
        GF2Matrix s = null;
        Permutation p;
        boolean found = false;

        do
        {
            p = new Permutation(n, sr);
            hp = (GF2Matrix)h.rightMultiply(p);
            sInv = hp.getLeftSubMatrix();
            try
            {
                found = true;
                s = (GF2Matrix)sInv.computeInverse();
            }
            catch (ArithmeticException ae)
            {
                found = false;
            }
        }
        while (!found);

        GF2Matrix shp = (GF2Matrix)s.rightMultiply(hp);
        GF2Matrix m = shp.getRightSubMatrix();

        return new MaMaPe(sInv, m, p);
    }

    /**
     * Find an error vector <tt>e</tt> over <tt>GF(2)</tt> from an input
     * syndrome <tt>s</tt> over <tt>GF(2<sup>m</sup>)</tt>.
     *
     * @param syndVec      the syndrome
     * @param field        the finite field
     * @param gp           the irreducible Goppa polynomial
     * @param sqRootMatrix the matrix for computing square roots in
     *                     <tt>(GF(2<sup>m</sup>))<sup>t</sup></tt>
     * @return the error vector
     */
    public static GF2Vector syndromeDecode(GF2Vector syndVec, GF2mField field,
                                           PolynomialGF2mSmallM gp, PolynomialGF2mSmallM[] sqRootMatrix)
    {

        int n = 1 << field.getDegree();

        // the error vector
        GF2Vector errors = new GF2Vector(n);

        // if the syndrome vector is zero, the error vector is also zero
        if (!syndVec.isZero())
        {
            // convert syndrome vector to polynomial over GF(2^m)
            PolynomialGF2mSmallM syndrome = new PolynomialGF2mSmallM(syndVec
                .toExtensionFieldVector(field));

            // compute T = syndrome^-1 mod gp
            PolynomialGF2mSmallM t = syndrome.modInverse(gp);

            // compute tau = sqRoot(T + X) mod gp
            PolynomialGF2mSmallM tau = t.addMonomial(1);
            tau = tau.modSquareRootMatrix(sqRootMatrix);

            // compute polynomials a and b satisfying a + b*tau = 0 mod gp
            PolynomialGF2mSmallM[] ab = tau.modPolynomialToFracton(gp);

            // compute the polynomial a^2 + X*b^2
            PolynomialGF2mSmallM a2 = ab[0].multiply(ab[0]);
            PolynomialGF2mSmallM b2 = ab[1].multiply(ab[1]);
            PolynomialGF2mSmallM xb2 = b2.multWithMonomial(1);
            PolynomialGF2mSmallM a2plusXb2 = a2.add(xb2);

            // normalize a^2 + X*b^2 to obtain the error locator polynomial
            int headCoeff = a2plusXb2.getHeadCoefficient();
            int invHeadCoeff = field.inverse(headCoeff);
            PolynomialGF2mSmallM elp = a2plusXb2.multWithElement(invHeadCoeff);

            // for all elements i of GF(2^m)
            for (int i = 0; i < n; i++)
            {
                // evaluate the error locator polynomial at i
                int z = elp.evaluateAt(i);
                // if polynomial evaluates to zero
                if (z == 0)
                {
                    // set the i-th coefficient of the error vector
                    errors.setBit(i);
                }
            }
        }

        return errors;
    }

}
