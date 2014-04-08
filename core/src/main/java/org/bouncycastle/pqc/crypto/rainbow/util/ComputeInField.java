package org.bouncycastle.pqc.crypto.rainbow.util;

/**
 * This class offers different operations on matrices in field GF2^8.
 * <p>
 * Implemented are functions:
 * - finding inverse of a matrix
 * - solving linear equation systems using the Gauss-Elimination method
 * - basic operations like matrix multiplication, addition and so on.
 */

public class ComputeInField
{

    private short[][] A; // used by solveEquation and inverse
    short[] x;

    /**
     * Constructor with no parameters
     */
    public ComputeInField()
    {
    }


    /**
     * This function finds a solution of the equation Bx = b.
     * Exception is thrown if the linear equation system has no solution
     *
     * @param B this matrix is the left part of the
     *          equation (B in the equation above)
     * @param b the right part of the equation
     *          (b in the equation above)
     * @return x  the solution of the equation if it is solvable
     *         null otherwise
     * @throws RuntimeException if LES is not solvable
     */
    public short[] solveEquation(short[][] B, short[] b)
    {
        try
        {

            if (B.length != b.length)
            {
                throw new RuntimeException(
                    "The equation system is not solvable");
            }

            /** initialize **/
            // this matrix stores B and b from the equation B*x = b
            // b is stored as the last column.
            // B contains one column more than rows.
            // In this column we store a free coefficient that should be later subtracted from b
            A = new short[B.length][B.length + 1];
            // stores the solution of the LES
            x = new short[B.length];

            /** copy B into the global matrix A **/
            for (int i = 0; i < B.length; i++)
            { // rows
                for (int j = 0; j < B[0].length; j++)
                { // cols
                    A[i][j] = B[i][j];
                }
            }

            /** copy the vector b into the global A **/
            //the free coefficient, stored in the last column of A( A[i][b.length]
            // is to be subtracted from b
            for (int i = 0; i < b.length; i++)
            {
                A[i][b.length] = GF2Field.addElem(b[i], A[i][b.length]);
            }

            /** call the methods for gauss elimination and backward substitution **/
            computeZerosUnder(false);     // obtain zeros under the diagonal
            substitute();

            return x;

        }
        catch (RuntimeException rte)
        {
            return null; // the LES is not solvable!
        }
    }

    /**
     * This function computes the inverse of a given matrix using the Gauss-
     * Elimination method.
     * <p>
     * An exception is thrown if the matrix has no inverse
     *
     * @param coef the matrix which inverse matrix is needed
     * @return inverse matrix of the input matrix.
     *         If the matrix is singular, null is returned.
     * @throws RuntimeException if the given matrix is not invertible
     */
    public short[][] inverse(short[][] coef)
    {
        try
        {
            /** Initialization: **/
            short factor;
            short[][] inverse;
            A = new short[coef.length][2 * coef.length];
            if (coef.length != coef[0].length)
            {
                throw new RuntimeException(
                    "The matrix is not invertible. Please choose another one!");
            }

            /** prepare: Copy coef and the identity matrix into the global A. **/
            for (int i = 0; i < coef.length; i++)
            {
                for (int j = 0; j < coef.length; j++)
                {
                    //copy the input matrix coef into A
                    A[i][j] = coef[i][j];
                }
                // copy the identity matrix into A.
                for (int j = coef.length; j < 2 * coef.length; j++)
                {
                    A[i][j] = 0;
                }
                A[i][i + A.length] = 1;
            }

            /** Elimination operations to get the identity matrix from the left side of A. **/
            // modify A to get 0s under the diagonal.
            computeZerosUnder(true);

            // modify A to get only 1s on the diagonal: A[i][j] =A[i][j]/A[i][i].
            for (int i = 0; i < A.length; i++)
            {
                factor = GF2Field.invElem(A[i][i]);
                for (int j = i; j < 2 * A.length; j++)
                {
                    A[i][j] = GF2Field.multElem(A[i][j], factor);
                }
            }

            //modify A to get only 0s above the diagonal.
            computeZerosAbove();

            // copy the result (the second half of A) in the matrix inverse.
            inverse = new short[A.length][A.length];
            for (int i = 0; i < A.length; i++)
            {
                for (int j = A.length; j < 2 * A.length; j++)
                {
                    inverse[i][j - A.length] = A[i][j];
                }
            }
            return inverse;

        }
        catch (RuntimeException rte)
        {
            // The matrix is not invertible! A new one should be generated!
            return null;
        }
    }

    /**
     * Elimination under the diagonal.
     * This function changes a matrix so that it contains only zeros under the
     * diagonal(Ai,i) using only Gauss-Elimination operations.
     * <p/>
     * It is used in solveEquaton as well as in the function for
     * finding an inverse of a matrix: {@link}inverse. Both of them use the
     * Gauss-Elimination Method.
     * <p/>
     * The result is stored in the global matrix A
     *
     * @param usedForInverse This parameter shows if the function is used by the
     *                       solveEquation-function or by the inverse-function and according
     *                       to this creates matrices of different sizes.
     * @throws RuntimeException in case a multiplicative inverse of 0 is needed
     */
    private void computeZerosUnder(boolean usedForInverse)
        throws RuntimeException
    {

        //the number of columns in the global A where the tmp results are stored
        int length;
        short tmp = 0;

        //the function is used in inverse() - A should have 2 times more columns than rows
        if (usedForInverse)
        {
            length = 2 * A.length;
        }
        //the function is used in solveEquation - A has 1 column more than rows
        else
        {
            length = A.length + 1;
        }

        //elimination operations to modify A so that that it contains only 0s under the diagonal
        for (int k = 0; k < A.length - 1; k++)
        { // the fixed row
            for (int i = k + 1; i < A.length; i++)
            { // rows
                short factor1 = A[i][k];
                short factor2 = GF2Field.invElem(A[k][k]);

                //The element which multiplicative inverse is needed, is 0
                //in this case is the input matrix not invertible
                if (factor2 == 0)
                {
                    throw new RuntimeException("Matrix not invertible! We have to choose another one!");
                }

                for (int j = k; j < length; j++)
                {// columns
                    // tmp=A[k,j] / A[k,k]
                    tmp = GF2Field.multElem(A[k][j], factor2);
                    // tmp = A[i,k] * A[k,j] / A[k,k]
                    tmp = GF2Field.multElem(factor1, tmp);
                    // A[i,j]=A[i,j]-A[i,k]/A[k,k]*A[k,j];
                    A[i][j] = GF2Field.addElem(A[i][j], tmp);
                }
            }
        }
    }

    /**
     * Elimination above the diagonal.
     * This function changes a matrix so that it contains only zeros above the
     * diagonal(Ai,i) using only Gauss-Elimination operations.
     * <p/>
     * It is used in the inverse-function
     * The result is stored in the global matrix A
     *
     * @throws RuntimeException in case a multiplicative inverse of 0 is needed
     */
    private void computeZerosAbove()
        throws RuntimeException
    {
        short tmp = 0;
        for (int k = A.length - 1; k > 0; k--)
        { // the fixed row
            for (int i = k - 1; i >= 0; i--)
            { // rows
                short factor1 = A[i][k];
                short factor2 = GF2Field.invElem(A[k][k]);
                if (factor2 == 0)
                {
                    throw new RuntimeException("The matrix is not invertible");
                }
                for (int j = k; j < 2 * A.length; j++)
                { // columns
                    // tmp = A[k,j] / A[k,k]
                    tmp = GF2Field.multElem(A[k][j], factor2);
                    // tmp = A[i,k] * A[k,j] / A[k,k]
                    tmp = GF2Field.multElem(factor1, tmp);
                    // A[i,j] = A[i,j] - A[i,k] / A[k,k] * A[k,j];
                    A[i][j] = GF2Field.addElem(A[i][j], tmp);
                }
            }
        }
    }


    /**
     * This function uses backward substitution to find x
     * of the linear equation system (LES) B*x = b,
     * where A a triangle-matrix is (contains only zeros under the diagonal)
     * and b is a vector
     * <p/>
     * If the multiplicative inverse of 0 is needed, an exception is thrown.
     * In this case is the LES not solvable
     *
     * @throws RuntimeException in case a multiplicative inverse of 0 is needed
     */
    private void substitute()
        throws RuntimeException
    {

        // for the temporary results of the operations in field
        short tmp, temp;

        temp = GF2Field.invElem(A[A.length - 1][A.length - 1]);
        if (temp == 0)
        {
            throw new RuntimeException("The equation system is not solvable");
        }

        /** backward substitution **/
        x[A.length - 1] = GF2Field.multElem(A[A.length - 1][A.length], temp);
        for (int i = A.length - 2; i >= 0; i--)
        {
            tmp = A[i][A.length];
            for (int j = A.length - 1; j > i; j--)
            {
                temp = GF2Field.multElem(A[i][j], x[j]);
                tmp = GF2Field.addElem(tmp, temp);
            }

            temp = GF2Field.invElem(A[i][i]);
            if (temp == 0)
            {
                throw new RuntimeException("Not solvable equation system");
            }
            x[i] = GF2Field.multElem(tmp, temp);
        }
    }


    /**
     * This function multiplies two given matrices.
     * If the given matrices cannot be multiplied due
     * to different sizes, an exception is thrown.
     *
     * @param M1 -the 1st matrix
     * @param M2 -the 2nd matrix
     * @return A = M1*M2
     * @throws RuntimeException in case the given matrices cannot be multiplied
     * due to different dimensions.
     */
    public short[][] multiplyMatrix(short[][] M1, short[][] M2)
        throws RuntimeException
    {

        if (M1[0].length != M2.length)
        {
            throw new RuntimeException("Multiplication is not possible!");
        }
        short tmp = 0;
        A = new short[M1.length][M2[0].length];
        for (int i = 0; i < M1.length; i++)
        {
            for (int j = 0; j < M2.length; j++)
            {
                for (int k = 0; k < M2[0].length; k++)
                {
                    tmp = GF2Field.multElem(M1[i][j], M2[j][k]);
                    A[i][k] = GF2Field.addElem(A[i][k], tmp);
                }
            }
        }
        return A;
    }

    /**
     * This function multiplies a given matrix with a one-dimensional array.
     * <p>
     * An exception is thrown, if the number of columns in the matrix and
     * the number of rows in the one-dim. array differ.
     *
     * @param M1 the matrix to be multiplied
     * @param m  the one-dimensional array to be multiplied
     * @return M1*m
     * @throws RuntimeException in case of dimension inconsistency
     */
    public short[] multiplyMatrix(short[][] M1, short[] m)
        throws RuntimeException
    {
        if (M1[0].length != m.length)
        {
            throw new RuntimeException("Multiplication is not possible!");
        }
        short tmp = 0;
        short[] B = new short[M1.length];
        for (int i = 0; i < M1.length; i++)
        {
            for (int j = 0; j < m.length; j++)
            {
                tmp = GF2Field.multElem(M1[i][j], m[j]);
                B[i] = GF2Field.addElem(B[i], tmp);
            }
        }
        return B;
    }

    /**
     * Addition of two vectors
     *
     * @param vector1 first summand, always of dim n
     * @param vector2 second summand, always of dim n
     * @return addition of vector1 and vector2
     * @throws RuntimeException in case the addition is impossible
     * due to inconsistency in the dimensions
     */
    public short[] addVect(short[] vector1, short[] vector2)
    {
        if (vector1.length != vector2.length)
        {
            throw new RuntimeException("Multiplication is not possible!");
        }
        short rslt[] = new short[vector1.length];
        for (int n = 0; n < rslt.length; n++)
        {
            rslt[n] = GF2Field.addElem(vector1[n], vector2[n]);
        }
        return rslt;
    }

    /**
     * Multiplication of column vector with row vector
     *
     * @param vector1 column vector, always n x 1
     * @param vector2 row vector, always 1 x n
     * @return resulting n x n matrix of multiplication
     * @throws RuntimeException in case the multiplication is impossible due to
     * inconsistency in the dimensions
     */
    public short[][] multVects(short[] vector1, short[] vector2)
    {
        if (vector1.length != vector2.length)
        {
            throw new RuntimeException("Multiplication is not possible!");
        }
        short rslt[][] = new short[vector1.length][vector2.length];
        for (int i = 0; i < vector1.length; i++)
        {
            for (int j = 0; j < vector2.length; j++)
            {
                rslt[i][j] = GF2Field.multElem(vector1[i], vector2[j]);
            }
        }
        return rslt;
    }

    /**
     * Multiplies vector with scalar
     *
     * @param scalar galois element to multiply vector with
     * @param vector vector to be multiplied
     * @return vector multiplied with scalar
     */
    public short[] multVect(short scalar, short[] vector)
    {
        short rslt[] = new short[vector.length];
        for (int n = 0; n < rslt.length; n++)
        {
            rslt[n] = GF2Field.multElem(scalar, vector[n]);
        }
        return rslt;
    }

    /**
     * Multiplies matrix with scalar
     *
     * @param scalar galois element to multiply matrix with
     * @param matrix 2-dim n x n matrix to be multiplied
     * @return matrix multiplied with scalar
     */
    public short[][] multMatrix(short scalar, short[][] matrix)
    {
        short[][] rslt = new short[matrix.length][matrix[0].length];
        for (int i = 0; i < matrix.length; i++)
        {
            for (int j = 0; j < matrix[0].length; j++)
            {
                rslt[i][j] = GF2Field.multElem(scalar, matrix[i][j]);
            }
        }
        return rslt;
    }

    /**
     * Adds the n x n matrices matrix1 and matrix2
     *
     * @param matrix1 first summand
     * @param matrix2 second summand
     * @return addition of matrix1 and matrix2; both having the dimensions n x n
     * @throws RuntimeException in case the addition is not possible because of
     * different dimensions of the matrices
     */
    public short[][] addSquareMatrix(short[][] matrix1, short[][] matrix2)
    {
        if (matrix1.length != matrix2.length || matrix1[0].length != matrix2[0].length)
        {
            throw new RuntimeException("Addition is not possible!");
        }

        short[][] rslt = new short[matrix1.length][matrix1.length];//
        for (int i = 0; i < matrix1.length; i++)
        {
            for (int j = 0; j < matrix2.length; j++)
            {
                rslt[i][j] = GF2Field.addElem(matrix1[i][j], matrix2[i][j]);
            }
        }
        return rslt;
    }

}
