package org.bouncycastle.pqc.math.linearalgebra;

import java.security.SecureRandom;

/**
 * This class describes some operations with matrices over finite field GF(2)
 * and is used in ecc and MQ-PKC (also has some specific methods and
 * implementation)
 */
public class GF2Matrix
    extends Matrix
{

    /**
     * For the matrix representation the array of type int[][] is used, thus one
     * element of the array keeps 32 elements of the matrix (from one row and 32
     * columns)
     */
    private int[][] matrix;

    /**
     * the length of each array representing a row of this matrix, computed as
     * <tt>(numColumns + 31) / 32</tt>
     */
    private int length;

    /**
     * Create the matrix from encoded form.
     *
     * @param enc the encoded matrix
     */
    public GF2Matrix(byte[] enc)
    {
        if (enc.length < 9)
        {
            throw new ArithmeticException(
                "given array is not an encoded matrix over GF(2)");
        }

        numRows = LittleEndianConversions.OS2IP(enc, 0);
        numColumns = LittleEndianConversions.OS2IP(enc, 4);

        int n = ((numColumns + 7) >>> 3) * numRows;

        if ((numRows <= 0) || (n != (enc.length - 8)))
        {
            throw new ArithmeticException(
                "given array is not an encoded matrix over GF(2)");
        }

        length = (numColumns + 31) >>> 5;
        matrix = new int[numRows][length];

        // number of "full" integer
        int q = numColumns >> 5;
        // number of bits in non-full integer
        int r = numColumns & 0x1f;

        int count = 8;
        for (int i = 0; i < numRows; i++)
        {
            for (int j = 0; j < q; j++, count += 4)
            {
                matrix[i][j] = LittleEndianConversions.OS2IP(enc, count);
            }
            for (int j = 0; j < r; j += 8)
            {
                matrix[i][q] ^= (enc[count++] & 0xff) << j;
            }
        }
    }

    /**
     * Create the matrix with the contents of the given array. The matrix is not
     * copied. Unused coefficients are masked out.
     *
     * @param numColumns the number of columns
     * @param matrix     the element array
     */
    public GF2Matrix(int numColumns, int[][] matrix)
    {
        if (matrix[0].length != (numColumns + 31) >> 5)
        {
            throw new ArithmeticException(
                "Int array does not match given number of columns.");
        }
        this.numColumns = numColumns;
        numRows = matrix.length;
        length = matrix[0].length;
        int rest = numColumns & 0x1f;
        int bitMask;
        if (rest == 0)
        {
            bitMask = 0xffffffff;
        }
        else
        {
            bitMask = (1 << rest) - 1;
        }
        for (int i = 0; i < numRows; i++)
        {
            matrix[i][length - 1] &= bitMask;
        }
        this.matrix = matrix;
    }

    /**
     * Create an nxn matrix of the given type.
     *
     * @param n            the number of rows (and columns)
     * @param typeOfMatrix the martix type (see {@link Matrix} for predefined
     *                     constants)
     */
    public GF2Matrix(int n, char typeOfMatrix)
    {
        this(n, typeOfMatrix, new java.security.SecureRandom());
    }

    /**
     * Create an nxn matrix of the given type.
     *
     * @param n            the matrix size
     * @param typeOfMatrix the matrix type
     * @param sr           the source of randomness
     */
    public GF2Matrix(int n, char typeOfMatrix, SecureRandom sr)
    {
        if (n <= 0)
        {
            throw new ArithmeticException("Size of matrix is non-positive.");
        }

        switch (typeOfMatrix)
        {

        case Matrix.MATRIX_TYPE_ZERO:
            assignZeroMatrix(n, n);
            break;

        case Matrix.MATRIX_TYPE_UNIT:
            assignUnitMatrix(n);
            break;

        case Matrix.MATRIX_TYPE_RANDOM_LT:
            assignRandomLowerTriangularMatrix(n, sr);
            break;

        case Matrix.MATRIX_TYPE_RANDOM_UT:
            assignRandomUpperTriangularMatrix(n, sr);
            break;

        case Matrix.MATRIX_TYPE_RANDOM_REGULAR:
            assignRandomRegularMatrix(n, sr);
            break;

        default:
            throw new ArithmeticException("Unknown matrix type.");
        }
    }

    /**
     * Copy constructor.
     *
     * @param a another {@link GF2Matrix}
     */
    public GF2Matrix(GF2Matrix a)
    {
        numColumns = a.getNumColumns();
        numRows = a.getNumRows();
        length = a.length;
        matrix = new int[a.matrix.length][];
        for (int i = 0; i < matrix.length; i++)
        {
            matrix[i] = IntUtils.clone(a.matrix[i]);
        }

    }

    /**
     * create the mxn zero matrix
     */
    private GF2Matrix(int m, int n)
    {
        if ((n <= 0) || (m <= 0))
        {
            throw new ArithmeticException("size of matrix is non-positive");
        }

        assignZeroMatrix(m, n);
    }

    /**
     * Create the mxn zero matrix.
     *
     * @param m number of rows
     * @param n number of columns
     */
    private void assignZeroMatrix(int m, int n)
    {
        numRows = m;
        numColumns = n;
        length = (n + 31) >>> 5;
        matrix = new int[numRows][length];
        for (int i = 0; i < numRows; i++)
        {
            for (int j = 0; j < length; j++)
            {
                matrix[i][j] = 0;
            }
        }
    }

    /**
     * Create the mxn unit matrix.
     *
     * @param n number of rows (and columns)
     */
    private void assignUnitMatrix(int n)
    {
        numRows = n;
        numColumns = n;
        length = (n + 31) >>> 5;
        matrix = new int[numRows][length];
        for (int i = 0; i < numRows; i++)
        {
            for (int j = 0; j < length; j++)
            {
                matrix[i][j] = 0;
            }
        }
        for (int i = 0; i < numRows; i++)
        {
            int rest = i & 0x1f;
            matrix[i][i >>> 5] = 1 << rest;
        }
    }

    /**
     * Create a nxn random lower triangular matrix.
     *
     * @param n  number of rows (and columns)
     * @param sr source of randomness
     */
    private void assignRandomLowerTriangularMatrix(int n, SecureRandom sr)
    {
        numRows = n;
        numColumns = n;
        length = (n + 31) >>> 5;
        matrix = new int[numRows][length];
        for (int i = 0; i < numRows; i++)
        {
            int q = i >>> 5;
            int r = i & 0x1f;
            int s = 31 - r;
            r = 1 << r;
            for (int j = 0; j < q; j++)
            {
                matrix[i][j] = sr.nextInt();
            }
            matrix[i][q] = (sr.nextInt() >>> s) | r;
            for (int j = q + 1; j < length; j++)
            {
                matrix[i][j] = 0;
            }

        }

    }

    /**
     * Create a nxn random upper triangular matrix.
     *
     * @param n  number of rows (and columns)
     * @param sr source of randomness
     */
    private void assignRandomUpperTriangularMatrix(int n, SecureRandom sr)
    {
        numRows = n;
        numColumns = n;
        length = (n + 31) >>> 5;
        matrix = new int[numRows][length];
        int rest = n & 0x1f;
        int help;
        if (rest == 0)
        {
            help = 0xffffffff;
        }
        else
        {
            help = (1 << rest) - 1;
        }
        for (int i = 0; i < numRows; i++)
        {
            int q = i >>> 5;
            int r = i & 0x1f;
            int s = r;
            r = 1 << r;
            for (int j = 0; j < q; j++)
            {
                matrix[i][j] = 0;
            }
            matrix[i][q] = (sr.nextInt() << s) | r;
            for (int j = q + 1; j < length; j++)
            {
                matrix[i][j] = sr.nextInt();
            }
            matrix[i][length - 1] &= help;
        }

    }

    /**
     * Create an nxn random regular matrix.
     *
     * @param n  number of rows (and columns)
     * @param sr source of randomness
     */
    private void assignRandomRegularMatrix(int n, SecureRandom sr)
    {
        numRows = n;
        numColumns = n;
        length = (n + 31) >>> 5;
        matrix = new int[numRows][length];
        GF2Matrix lm = new GF2Matrix(n, Matrix.MATRIX_TYPE_RANDOM_LT, sr);
        GF2Matrix um = new GF2Matrix(n, Matrix.MATRIX_TYPE_RANDOM_UT, sr);
        GF2Matrix rm = (GF2Matrix)lm.rightMultiply(um);
        Permutation perm = new Permutation(n, sr);
        int[] p = perm.getVector();
        for (int i = 0; i < n; i++)
        {
            System.arraycopy(rm.matrix[i], 0, matrix[p[i]], 0, length);
        }
    }

    /**
     * Create a nxn random regular matrix and its inverse.
     *
     * @param n  number of rows (and columns)
     * @param sr source of randomness
     * @return the created random regular matrix and its inverse
     */
    public static GF2Matrix[] createRandomRegularMatrixAndItsInverse(int n,
                                                                     SecureRandom sr)
    {

        GF2Matrix[] result = new GF2Matrix[2];

        // ------------------------------------
        // First part: create regular matrix
        // ------------------------------------

        // ------
        int length = (n + 31) >> 5;
        GF2Matrix lm = new GF2Matrix(n, Matrix.MATRIX_TYPE_RANDOM_LT, sr);
        GF2Matrix um = new GF2Matrix(n, Matrix.MATRIX_TYPE_RANDOM_UT, sr);
        GF2Matrix rm = (GF2Matrix)lm.rightMultiply(um);
        Permutation p = new Permutation(n, sr);
        int[] pVec = p.getVector();

        int[][] matrix = new int[n][length];
        for (int i = 0; i < n; i++)
        {
            System.arraycopy(rm.matrix[pVec[i]], 0, matrix[i], 0, length);
        }

        result[0] = new GF2Matrix(n, matrix);

        // ------------------------------------
        // Second part: create inverse matrix
        // ------------------------------------

        // inverse to lm
        GF2Matrix invLm = new GF2Matrix(n, Matrix.MATRIX_TYPE_UNIT);
        for (int i = 0; i < n; i++)
        {
            int rest = i & 0x1f;
            int q = i >>> 5;
            int r = 1 << rest;
            for (int j = i + 1; j < n; j++)
            {
                int b = (lm.matrix[j][q]) & r;
                if (b != 0)
                {
                    for (int k = 0; k <= q; k++)
                    {
                        invLm.matrix[j][k] ^= invLm.matrix[i][k];
                    }
                }
            }
        }
        // inverse to um
        GF2Matrix invUm = new GF2Matrix(n, Matrix.MATRIX_TYPE_UNIT);
        for (int i = n - 1; i >= 0; i--)
        {
            int rest = i & 0x1f;
            int q = i >>> 5;
            int r = 1 << rest;
            for (int j = i - 1; j >= 0; j--)
            {
                int b = (um.matrix[j][q]) & r;
                if (b != 0)
                {
                    for (int k = q; k < length; k++)
                    {
                        invUm.matrix[j][k] ^= invUm.matrix[i][k];
                    }
                }
            }
        }

        // inverse matrix
        result[1] = (GF2Matrix)invUm.rightMultiply(invLm.rightMultiply(p));

        return result;
    }

    /**
     * @return the array keeping the matrix elements
     */
    public int[][] getIntArray()
    {
        return matrix;
    }

    /**
     * @return the length of each array representing a row of this matrix
     */
    public int getLength()
    {
        return length;
    }

    /**
     * Return the row of this matrix with the given index.
     *
     * @param index the index
     * @return the row of this matrix with the given index
     */
    public int[] getRow(int index)
    {
        return matrix[index];
    }

    /**
     * Returns encoded matrix, i.e., this matrix in byte array form
     *
     * @return the encoded matrix
     */
    public byte[] getEncoded()
    {
        int n = (numColumns + 7) >>> 3;
        n *= numRows;
        n += 8;
        byte[] enc = new byte[n];

        LittleEndianConversions.I2OSP(numRows, enc, 0);
        LittleEndianConversions.I2OSP(numColumns, enc, 4);

        // number of "full" integer
        int q = numColumns >>> 5;
        // number of bits in non-full integer
        int r = numColumns & 0x1f;

        int count = 8;
        for (int i = 0; i < numRows; i++)
        {
            for (int j = 0; j < q; j++, count += 4)
            {
                LittleEndianConversions.I2OSP(matrix[i][j], enc, count);
            }
            for (int j = 0; j < r; j += 8)
            {
                enc[count++] = (byte)((matrix[i][q] >>> j) & 0xff);
            }

        }
        return enc;
    }


    /**
     * Returns the percentage of the number of "ones" in this matrix.
     *
     * @return the Hamming weight of this matrix (as a ratio).
     */
    public double getHammingWeight()
    {
        double counter = 0.0;
        double elementCounter = 0.0;
        int rest = numColumns & 0x1f;
        int d;
        if (rest == 0)
        {
            d = length;
        }
        else
        {
            d = length - 1;
        }

        for (int i = 0; i < numRows; i++)
        {

            for (int j = 0; j < d; j++)
            {
                int a = matrix[i][j];
                for (int k = 0; k < 32; k++)
                {
                    int b = (a >>> k) & 1;
                    counter = counter + b;
                    elementCounter = elementCounter + 1;
                }
            }
            int a = matrix[i][length - 1];
            for (int k = 0; k < rest; k++)
            {
                int b = (a >>> k) & 1;
                counter = counter + b;
                elementCounter = elementCounter + 1;
            }
        }

        return counter / elementCounter;
    }

    /**
     * Check if this is the zero matrix (i.e., all entries are zero).
     *
     * @return <tt>true</tt> if this is the zero matrix
     */
    public boolean isZero()
    {
        for (int i = 0; i < numRows; i++)
        {
            for (int j = 0; j < length; j++)
            {
                if (matrix[i][j] != 0)
                {
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * Get the quadratic submatrix of this matrix consisting of the leftmost
     * <tt>numRows</tt> columns.
     *
     * @return the <tt>(numRows x numRows)</tt> submatrix
     */
    public GF2Matrix getLeftSubMatrix()
    {
        if (numColumns <= numRows)
        {
            throw new ArithmeticException("empty submatrix");
        }
        int length = (numRows + 31) >> 5;
        int[][] result = new int[numRows][length];
        int bitMask = (1 << (numRows & 0x1f)) - 1;
        if (bitMask == 0)
        {
            bitMask = -1;
        }
        for (int i = numRows - 1; i >= 0; i--)
        {
            System.arraycopy(matrix[i], 0, result[i], 0, length);
            result[i][length - 1] &= bitMask;
        }
        return new GF2Matrix(numRows, result);
    }

    /**
     * Compute the full form matrix <tt>(this | Id)</tt> from this matrix in
     * left compact form, where <tt>Id</tt> is the <tt>k x k</tt> identity
     * matrix and <tt>k</tt> is the number of rows of this matrix.
     *
     * @return <tt>(this | Id)</tt>
     */
    public GF2Matrix extendLeftCompactForm()
    {
        int newNumColumns = numColumns + numRows;
        GF2Matrix result = new GF2Matrix(numRows, newNumColumns);

        int ind = numRows - 1 + numColumns;
        for (int i = numRows - 1; i >= 0; i--, ind--)
        {
            // copy this matrix to first columns
            System.arraycopy(matrix[i], 0, result.matrix[i], 0, length);
            // store the identity in last columns
            result.matrix[i][ind >> 5] |= 1 << (ind & 0x1f);
        }

        return result;
    }

    /**
     * Get the submatrix of this matrix consisting of the rightmost
     * <tt>numColumns-numRows</tt> columns.
     *
     * @return the <tt>(numRows x (numColumns-numRows))</tt> submatrix
     */
    public GF2Matrix getRightSubMatrix()
    {
        if (numColumns <= numRows)
        {
            throw new ArithmeticException("empty submatrix");
        }

        int q = numRows >> 5;
        int r = numRows & 0x1f;

        GF2Matrix result = new GF2Matrix(numRows, numColumns - numRows);

        for (int i = numRows - 1; i >= 0; i--)
        {
            // if words have to be shifted
            if (r != 0)
            {
                int ind = q;
                // process all but last word
                for (int j = 0; j < result.length - 1; j++)
                {
                    // shift to correct position
                    result.matrix[i][j] = (matrix[i][ind++] >>> r)
                        | (matrix[i][ind] << (32 - r));
                }
                // process last word
                result.matrix[i][result.length - 1] = matrix[i][ind++] >>> r;
                if (ind < length)
                {
                    result.matrix[i][result.length - 1] |= matrix[i][ind] << (32 - r);
                }
            }
            else
            {
                // no shifting necessary
                System.arraycopy(matrix[i], q, result.matrix[i], 0,
                    result.length);
            }
        }
        return result;
    }

    /**
     * Compute the full form matrix <tt>(Id | this)</tt> from this matrix in
     * right compact form, where <tt>Id</tt> is the <tt>k x k</tt> identity
     * matrix and <tt>k</tt> is the number of rows of this matrix.
     *
     * @return <tt>(Id | this)</tt>
     */
    public GF2Matrix extendRightCompactForm()
    {
        GF2Matrix result = new GF2Matrix(numRows, numRows + numColumns);

        int q = numRows >> 5;
        int r = numRows & 0x1f;

        for (int i = numRows - 1; i >= 0; i--)
        {
            // store the identity in first columns
            result.matrix[i][i >> 5] |= 1 << (i & 0x1f);

            // copy this matrix to last columns

            // if words have to be shifted
            if (r != 0)
            {
                int ind = q;
                // process all but last word
                for (int j = 0; j < length - 1; j++)
                {
                    // obtain matrix word
                    int mw = matrix[i][j];
                    // shift to correct position
                    result.matrix[i][ind++] |= mw << r;
                    result.matrix[i][ind] |= mw >>> (32 - r);
                }
                // process last word
                int mw = matrix[i][length - 1];
                result.matrix[i][ind++] |= mw << r;
                if (ind < result.length)
                {
                    result.matrix[i][ind] |= mw >>> (32 - r);
                }
            }
            else
            {
                // no shifting necessary
                System.arraycopy(matrix[i], 0, result.matrix[i], q, length);
            }
        }

        return result;
    }

    /**
     * Compute the transpose of this matrix.
     *
     * @return <tt>(this)<sup>T</sup></tt>
     */
    public Matrix computeTranspose()
    {
        int[][] result = new int[numColumns][(numRows + 31) >>> 5];
        for (int i = 0; i < numRows; i++)
        {
            for (int j = 0; j < numColumns; j++)
            {
                int qs = j >>> 5;
                int rs = j & 0x1f;
                int b = (matrix[i][qs] >>> rs) & 1;
                int qt = i >>> 5;
                int rt = i & 0x1f;
                if (b == 1)
                {
                    result[j][qt] |= 1 << rt;
                }
            }
        }

        return new GF2Matrix(numRows, result);
    }

    /**
     * Compute the inverse of this matrix.
     *
     * @return the inverse of this matrix (newly created).
     * @throws ArithmeticException if this matrix is not invertible.
     */
    public Matrix computeInverse()
    {
        if (numRows != numColumns)
        {
            throw new ArithmeticException("Matrix is not invertible.");
        }

        // clone this matrix
        int[][] tmpMatrix = new int[numRows][length];
        for (int i = numRows - 1; i >= 0; i--)
        {
            tmpMatrix[i] = IntUtils.clone(matrix[i]);
        }

        // initialize inverse matrix as unit matrix
        int[][] invMatrix = new int[numRows][length];
        for (int i = numRows - 1; i >= 0; i--)
        {
            int q = i >> 5;
            int r = i & 0x1f;
            invMatrix[i][q] = 1 << r;
        }

        // simultaneously compute Gaussian reduction of tmpMatrix and unit
        // matrix
        for (int i = 0; i < numRows; i++)
        {
            // i = q * 32 + (i mod 32)
            int q = i >> 5;
            int bitMask = 1 << (i & 0x1f);
            // if diagonal element is zero
            if ((tmpMatrix[i][q] & bitMask) == 0)
            {
                boolean foundNonZero = false;
                // find a non-zero element in the same column
                for (int j = i + 1; j < numRows; j++)
                {
                    if ((tmpMatrix[j][q] & bitMask) != 0)
                    {
                        // found it, swap rows ...
                        foundNonZero = true;
                        swapRows(tmpMatrix, i, j);
                        swapRows(invMatrix, i, j);
                        // ... and quit searching
                        j = numRows;
                        continue;
                    }
                }
                // if no non-zero element was found ...
                if (!foundNonZero)
                {
                    // ... the matrix is not invertible
                    throw new ArithmeticException("Matrix is not invertible.");
                }
            }

            // normalize all but i-th row
            for (int j = numRows - 1; j >= 0; j--)
            {
                if ((j != i) && ((tmpMatrix[j][q] & bitMask) != 0))
                {
                    addToRow(tmpMatrix[i], tmpMatrix[j], q);
                    addToRow(invMatrix[i], invMatrix[j], 0);
                }
            }
        }

        return new GF2Matrix(numColumns, invMatrix);
    }

    /**
     * Compute the product of a permutation matrix (which is generated from an
     * n-permutation) and this matrix.
     *
     * @param p the permutation
     * @return {@link GF2Matrix} <tt>P*this</tt>
     */
    public Matrix leftMultiply(Permutation p)
    {
        int[] pVec = p.getVector();
        if (pVec.length != numRows)
        {
            throw new ArithmeticException("length mismatch");
        }

        int[][] result = new int[numRows][];

        for (int i = numRows - 1; i >= 0; i--)
        {
            result[i] = IntUtils.clone(matrix[pVec[i]]);
        }

        return new GF2Matrix(numRows, result);
    }

    /**
     * compute product a row vector and this matrix
     *
     * @param vec a vector over GF(2)
     * @return Vector product a*matrix
     */
    public Vector leftMultiply(Vector vec)
    {

        if (!(vec instanceof GF2Vector))
        {
            throw new ArithmeticException("vector is not defined over GF(2)");
        }

        if (vec.length != numRows)
        {
            throw new ArithmeticException("length mismatch");
        }

        int[] v = ((GF2Vector)vec).getVecArray();
        int[] res = new int[length];

        int q = numRows >> 5;
        int r = 1 << (numRows & 0x1f);

        // compute scalar products with full words of vector
        int row = 0;
        for (int i = 0; i < q; i++)
        {
            int bitMask = 1;
            do
            {
                int b = v[i] & bitMask;
                if (b != 0)
                {
                    for (int j = 0; j < length; j++)
                    {
                        res[j] ^= matrix[row][j];
                    }
                }
                row++;
                bitMask <<= 1;
            }
            while (bitMask != 0);
        }

        // compute scalar products with last word of vector
        int bitMask = 1;
        while (bitMask != r)
        {
            int b = v[q] & bitMask;
            if (b != 0)
            {
                for (int j = 0; j < length; j++)
                {
                    res[j] ^= matrix[row][j];
                }
            }
            row++;
            bitMask <<= 1;
        }

        return new GF2Vector(res, numColumns);
    }

    /**
     * Compute the product of the matrix <tt>(this | Id)</tt> and a column
     * vector, where <tt>Id</tt> is a <tt>(numRows x numRows)</tt> unit
     * matrix.
     *
     * @param vec the vector over GF(2)
     * @return <tt>(this | Id)*vector</tt>
     */
    public Vector leftMultiplyLeftCompactForm(Vector vec)
    {
        if (!(vec instanceof GF2Vector))
        {
            throw new ArithmeticException("vector is not defined over GF(2)");
        }

        if (vec.length != numRows)
        {
            throw new ArithmeticException("length mismatch");
        }

        int[] v = ((GF2Vector)vec).getVecArray();
        int[] res = new int[(numRows + numColumns + 31) >>> 5];

        // process full words of vector
        int words = numRows >>> 5;
        int row = 0;
        for (int i = 0; i < words; i++)
        {
            int bitMask = 1;
            do
            {
                int b = v[i] & bitMask;
                if (b != 0)
                {
                    // compute scalar product part
                    for (int j = 0; j < length; j++)
                    {
                        res[j] ^= matrix[row][j];
                    }
                    // set last bit
                    int q = (numColumns + row) >>> 5;
                    int r = (numColumns + row) & 0x1f;
                    res[q] |= 1 << r;
                }
                row++;
                bitMask <<= 1;
            }
            while (bitMask != 0);
        }

        // process last word of vector
        int rem = 1 << (numRows & 0x1f);
        int bitMask = 1;
        while (bitMask != rem)
        {
            int b = v[words] & bitMask;
            if (b != 0)
            {
                // compute scalar product part
                for (int j = 0; j < length; j++)
                {
                    res[j] ^= matrix[row][j];
                }
                // set last bit
                int q = (numColumns + row) >>> 5;
                int r = (numColumns + row) & 0x1f;
                res[q] |= 1 << r;
            }
            row++;
            bitMask <<= 1;
        }

        return new GF2Vector(res, numRows + numColumns);
    }

    /**
     * Compute the product of this matrix and a matrix A over GF(2).
     *
     * @param mat a matrix A over GF(2)
     * @return matrix product <tt>this*matrixA</tt>
     */
    public Matrix rightMultiply(Matrix mat)
    {
        if (!(mat instanceof GF2Matrix))
        {
            throw new ArithmeticException("matrix is not defined over GF(2)");
        }

        if (mat.numRows != numColumns)
        {
            throw new ArithmeticException("length mismatch");
        }

        GF2Matrix a = (GF2Matrix)mat;
        GF2Matrix result = new GF2Matrix(numRows, mat.numColumns);

        int d;
        int rest = numColumns & 0x1f;
        if (rest == 0)
        {
            d = length;
        }
        else
        {
            d = length - 1;
        }
        for (int i = 0; i < numRows; i++)
        {
            int count = 0;
            for (int j = 0; j < d; j++)
            {
                int e = matrix[i][j];
                for (int h = 0; h < 32; h++)
                {
                    int b = e & (1 << h);
                    if (b != 0)
                    {
                        for (int g = 0; g < a.length; g++)
                        {
                            result.matrix[i][g] ^= a.matrix[count][g];
                        }
                    }
                    count++;
                }
            }
            int e = matrix[i][length - 1];
            for (int h = 0; h < rest; h++)
            {
                int b = e & (1 << h);
                if (b != 0)
                {
                    for (int g = 0; g < a.length; g++)
                    {
                        result.matrix[i][g] ^= a.matrix[count][g];
                    }
                }
                count++;
            }

        }

        return result;
    }

    /**
     * Compute the product of this matrix and a permutation matrix which is
     * generated from an n-permutation.
     *
     * @param p the permutation
     * @return {@link GF2Matrix} <tt>this*P</tt>
     */
    public Matrix rightMultiply(Permutation p)
    {

        int[] pVec = p.getVector();
        if (pVec.length != numColumns)
        {
            throw new ArithmeticException("length mismatch");
        }

        GF2Matrix result = new GF2Matrix(numRows, numColumns);

        for (int i = numColumns - 1; i >= 0; i--)
        {
            int q = i >>> 5;
            int r = i & 0x1f;
            int pq = pVec[i] >>> 5;
            int pr = pVec[i] & 0x1f;
            for (int j = numRows - 1; j >= 0; j--)
            {
                result.matrix[j][q] |= ((matrix[j][pq] >>> pr) & 1) << r;
            }
        }

        return result;
    }

    /**
     * Compute the product of this matrix and the given column vector.
     *
     * @param vec the vector over GF(2)
     * @return <tt>this*vector</tt>
     */
    public Vector rightMultiply(Vector vec)
    {
        if (!(vec instanceof GF2Vector))
        {
            throw new ArithmeticException("vector is not defined over GF(2)");
        }

        if (vec.length != numColumns)
        {
            throw new ArithmeticException("length mismatch");
        }

        int[] v = ((GF2Vector)vec).getVecArray();
        int[] res = new int[(numRows + 31) >>> 5];

        for (int i = 0; i < numRows; i++)
        {
            // compute full word scalar products
            int help = 0;
            for (int j = 0; j < length; j++)
            {
                help ^= matrix[i][j] & v[j];
            }
            // compute single word scalar product
            int bitValue = 0;
            for (int j = 0; j < 32; j++)
            {
                bitValue ^= (help >>> j) & 1;
            }
            // set result bit
            if (bitValue == 1)
            {
                res[i >>> 5] |= 1 << (i & 0x1f);
            }
        }

        return new GF2Vector(res, numRows);
    }

    /**
     * Compute the product of the matrix <tt>(Id | this)</tt> and a column
     * vector, where <tt>Id</tt> is a <tt>(numRows x numRows)</tt> unit
     * matrix.
     *
     * @param vec the vector over GF(2)
     * @return <tt>(Id | this)*vector</tt>
     */
    public Vector rightMultiplyRightCompactForm(Vector vec)
    {
        if (!(vec instanceof GF2Vector))
        {
            throw new ArithmeticException("vector is not defined over GF(2)");
        }

        if (vec.length != numColumns + numRows)
        {
            throw new ArithmeticException("length mismatch");
        }

        int[] v = ((GF2Vector)vec).getVecArray();
        int[] res = new int[(numRows + 31) >>> 5];

        int q = numRows >> 5;
        int r = numRows & 0x1f;

        // for all rows
        for (int i = 0; i < numRows; i++)
        {
            // get vector bit
            int help = (v[i >> 5] >>> (i & 0x1f)) & 1;

            // compute full word scalar products
            int vInd = q;
            // if words have to be shifted
            if (r != 0)
            {
                int vw = 0;
                // process all but last word
                for (int j = 0; j < length - 1; j++)
                {
                    // shift to correct position
                    vw = (v[vInd++] >>> r) | (v[vInd] << (32 - r));
                    help ^= matrix[i][j] & vw;
                }
                // process last word
                vw = v[vInd++] >>> r;
                if (vInd < v.length)
                {
                    vw |= v[vInd] << (32 - r);
                }
                help ^= matrix[i][length - 1] & vw;
            }
            else
            {
                // no shifting necessary
                for (int j = 0; j < length; j++)
                {
                    help ^= matrix[i][j] & v[vInd++];
                }
            }

            // compute single word scalar product
            int bitValue = 0;
            for (int j = 0; j < 32; j++)
            {
                bitValue ^= help & 1;
                help >>>= 1;
            }

            // set result bit
            if (bitValue == 1)
            {
                res[i >> 5] |= 1 << (i & 0x1f);
            }
        }

        return new GF2Vector(res, numRows);
    }

    /**
     * Compare this matrix with another object.
     *
     * @param other another object
     * @return the result of the comparison
     */
    public boolean equals(Object other)
    {

        if (!(other instanceof GF2Matrix))
        {
            return false;
        }
        GF2Matrix otherMatrix = (GF2Matrix)other;

        if ((numRows != otherMatrix.numRows)
            || (numColumns != otherMatrix.numColumns)
            || (length != otherMatrix.length))
        {
            return false;
        }

        for (int i = 0; i < numRows; i++)
        {
            if (!IntUtils.equals(matrix[i], otherMatrix.matrix[i]))
            {
                return false;
            }
        }

        return true;
    }

    /**
     * @return the hash code of this matrix
     */
    public int hashCode()
    {
        int hash = (numRows * 31 + numColumns) * 31 + length;
        for (int i = 0; i < numRows; i++)
        {
            hash = hash * 31 + matrix[i].hashCode();
        }
        return hash;
    }

    /**
     * @return a human readable form of the matrix
     */
    public String toString()
    {
        int rest = numColumns & 0x1f;
        int d;
        if (rest == 0)
        {
            d = length;
        }
        else
        {
            d = length - 1;
        }

        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < numRows; i++)
        {
            buf.append(i + ": ");
            for (int j = 0; j < d; j++)
            {
                int a = matrix[i][j];
                for (int k = 0; k < 32; k++)
                {
                    int b = (a >>> k) & 1;
                    if (b == 0)
                    {
                        buf.append('0');
                    }
                    else
                    {
                        buf.append('1');
                    }
                }
                buf.append(' ');
            }
            int a = matrix[i][length - 1];
            for (int k = 0; k < rest; k++)
            {
                int b = (a >>> k) & 1;
                if (b == 0)
                {
                    buf.append('0');
                }
                else
                {
                    buf.append('1');
                }
            }
            buf.append('\n');
        }

        return buf.toString();
    }

    /**
     * Swap two rows of the given matrix.
     *
     * @param matrix the matrix
     * @param first  the index of the first row
     * @param second the index of the second row
     */
    private static void swapRows(int[][] matrix, int first, int second)
    {
        int[] tmp = matrix[first];
        matrix[first] = matrix[second];
        matrix[second] = tmp;
    }

    /**
     * Partially add one row to another.
     *
     * @param fromRow    the addend
     * @param toRow      the row to add to
     * @param startIndex the array index to start from
     */
    private static void addToRow(int[] fromRow, int[] toRow, int startIndex)
    {
        for (int i = toRow.length - 1; i >= startIndex; i--)
        {
            toRow[i] = fromRow[i] ^ toRow[i];
        }
    }

}
