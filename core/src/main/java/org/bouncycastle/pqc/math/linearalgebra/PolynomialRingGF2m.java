package org.bouncycastle.pqc.math.linearalgebra;

/**
 * This class represents polynomial rings <tt>GF(2^m)[X]/p(X)</tt> for
 * <tt>m&lt;32</tt>. If <tt>p(X)</tt> is irreducible, the polynomial ring
 * is in fact an extension field of <tt>GF(2^m)</tt>.
 */
public class PolynomialRingGF2m
{

    /**
     * the finite field this polynomial ring is defined over
     */
    private GF2mField field;

    /**
     * the reduction polynomial
     */
    private PolynomialGF2mSmallM p;

    /**
     * the squaring matrix for this polynomial ring (given as the array of its
     * row vectors)
     */
    protected PolynomialGF2mSmallM[] sqMatrix;

    /**
     * the matrix for computing square roots in this polynomial ring (given as
     * the array of its row vectors). This matrix is computed as the inverse of
     * the squaring matrix.
     */
    protected PolynomialGF2mSmallM[] sqRootMatrix;

    /**
     * Constructor.
     *
     * @param field the finite field
     * @param p     the reduction polynomial
     */
    public PolynomialRingGF2m(GF2mField field, PolynomialGF2mSmallM p)
    {
        this.field = field;
        this.p = p;
        computeSquaringMatrix();
        computeSquareRootMatrix();
    }

    /**
     * @return the squaring matrix for this polynomial ring
     */
    public PolynomialGF2mSmallM[] getSquaringMatrix()
    {
        return sqMatrix;
    }

    /**
     * @return the matrix for computing square roots for this polynomial ring
     */
    public PolynomialGF2mSmallM[] getSquareRootMatrix()
    {
        return sqRootMatrix;
    }

    /**
     * Compute the squaring matrix for this polynomial ring, using the base
     * field and the reduction polynomial.
     */
    private void computeSquaringMatrix()
    {
        int numColumns = p.getDegree();
        sqMatrix = new PolynomialGF2mSmallM[numColumns];
        for (int i = 0; i < numColumns >> 1; i++)
        {
            int[] monomCoeffs = new int[(i << 1) + 1];
            monomCoeffs[i << 1] = 1;
            sqMatrix[i] = new PolynomialGF2mSmallM(field, monomCoeffs);
        }
        for (int i = numColumns >> 1; i < numColumns; i++)
        {
            int[] monomCoeffs = new int[(i << 1) + 1];
            monomCoeffs[i << 1] = 1;
            PolynomialGF2mSmallM monomial = new PolynomialGF2mSmallM(field,
                monomCoeffs);
            sqMatrix[i] = monomial.mod(p);
        }
    }

    /**
     * Compute the matrix for computing square roots in this polynomial ring by
     * inverting the squaring matrix.
     */
    private void computeSquareRootMatrix()
    {
        int numColumns = p.getDegree();

        // clone squaring matrix
        PolynomialGF2mSmallM[] tmpMatrix = new PolynomialGF2mSmallM[numColumns];
        for (int i = numColumns - 1; i >= 0; i--)
        {
            tmpMatrix[i] = new PolynomialGF2mSmallM(sqMatrix[i]);
        }

        // initialize square root matrix as unit matrix
        sqRootMatrix = new PolynomialGF2mSmallM[numColumns];
        for (int i = numColumns - 1; i >= 0; i--)
        {
            sqRootMatrix[i] = new PolynomialGF2mSmallM(field, i);
        }

        // simultaneously compute Gaussian reduction of squaring matrix and unit
        // matrix
        for (int i = 0; i < numColumns; i++)
        {
            // if diagonal element is zero
            if (tmpMatrix[i].getCoefficient(i) == 0)
            {
                boolean foundNonZero = false;
                // find a non-zero element in the same row
                for (int j = i + 1; j < numColumns; j++)
                {
                    if (tmpMatrix[j].getCoefficient(i) != 0)
                    {
                        // found it, swap columns ...
                        foundNonZero = true;
                        swapColumns(tmpMatrix, i, j);
                        swapColumns(sqRootMatrix, i, j);
                        // ... and quit searching
                        j = numColumns;
                        continue;
                    }
                }
                // if no non-zero element was found
                if (!foundNonZero)
                {
                    // the matrix is not invertible
                    throw new ArithmeticException(
                        "Squaring matrix is not invertible.");
                }
            }

            // normalize i-th column
            int coef = tmpMatrix[i].getCoefficient(i);
            int invCoef = field.inverse(coef);
            tmpMatrix[i].multThisWithElement(invCoef);
            sqRootMatrix[i].multThisWithElement(invCoef);

            // normalize all other columns
            for (int j = 0; j < numColumns; j++)
            {
                if (j != i)
                {
                    coef = tmpMatrix[j].getCoefficient(i);
                    if (coef != 0)
                    {
                        PolynomialGF2mSmallM tmpSqColumn = tmpMatrix[i]
                            .multWithElement(coef);
                        PolynomialGF2mSmallM tmpInvColumn = sqRootMatrix[i]
                            .multWithElement(coef);
                        tmpMatrix[j].addToThis(tmpSqColumn);
                        sqRootMatrix[j].addToThis(tmpInvColumn);
                    }
                }
            }
        }
    }

    private static void swapColumns(PolynomialGF2mSmallM[] matrix, int first,
                                    int second)
    {
        PolynomialGF2mSmallM tmp = matrix[first];
        matrix[first] = matrix[second];
        matrix[second] = tmp;
    }

}
