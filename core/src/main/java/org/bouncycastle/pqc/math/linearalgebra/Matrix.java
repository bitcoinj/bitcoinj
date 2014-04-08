package org.bouncycastle.pqc.math.linearalgebra;

/**
 * This abstract class defines matrices. It holds the number of rows and the
 * number of columns of the matrix and defines some basic methods.
 */
public abstract class Matrix
{

    /**
     * number of rows
     */
    protected int numRows;

    /**
     * number of columns
     */
    protected int numColumns;

    // ----------------------------------------------------
    // some constants (matrix types)
    // ----------------------------------------------------

    /**
     * zero matrix
     */
    public static final char MATRIX_TYPE_ZERO = 'Z';

    /**
     * unit matrix
     */
    public static final char MATRIX_TYPE_UNIT = 'I';

    /**
     * random lower triangular matrix
     */
    public static final char MATRIX_TYPE_RANDOM_LT = 'L';

    /**
     * random upper triangular matrix
     */
    public static final char MATRIX_TYPE_RANDOM_UT = 'U';

    /**
     * random regular matrix
     */
    public static final char MATRIX_TYPE_RANDOM_REGULAR = 'R';

    // ----------------------------------------------------
    // getters
    // ----------------------------------------------------

    /**
     * @return the number of rows in the matrix
     */
    public int getNumRows()
    {
        return numRows;
    }

    /**
     * @return the number of columns in the binary matrix
     */
    public int getNumColumns()
    {
        return numColumns;
    }

    /**
     * @return the encoded matrix, i.e., this matrix in byte array form.
     */
    public abstract byte[] getEncoded();

    // ----------------------------------------------------
    // arithmetic
    // ----------------------------------------------------

    /**
     * Compute the inverse of this matrix.
     *
     * @return the inverse of this matrix (newly created).
     */
    public abstract Matrix computeInverse();

    /**
     * Check if this is the zero matrix (i.e., all entries are zero).
     *
     * @return <tt>true</tt> if this is the zero matrix
     */
    public abstract boolean isZero();

    /**
     * Compute the product of this matrix and another matrix.
     *
     * @param a the other matrix
     * @return <tt>this * a</tt> (newly created)
     */
    public abstract Matrix rightMultiply(Matrix a);

    /**
     * Compute the product of this matrix and a permutation.
     *
     * @param p the permutation
     * @return <tt>this * p</tt> (newly created)
     */
    public abstract Matrix rightMultiply(Permutation p);

    /**
     * Compute the product of a vector and this matrix. If the length of the
     * vector is greater than the number of rows of this matrix, the matrix is
     * multiplied by each m-bit part of the vector.
     *
     * @param vector a vector
     * @return <tt>vector * this</tt> (newly created)
     */
    public abstract Vector leftMultiply(Vector vector);

    /**
     * Compute the product of this matrix and a vector.
     *
     * @param vector a vector
     * @return <tt>this * vector</tt> (newly created)
     */
    public abstract Vector rightMultiply(Vector vector);

    /**
     * @return a human readable form of the matrix.
     */
    public abstract String toString();

}
