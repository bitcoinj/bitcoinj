package org.bouncycastle.pqc.math.ntru.polynomial;

/**
 * A polynomial whose coefficients are all equal to -1, 0, or 1
 */
public interface TernaryPolynomial
    extends Polynomial
{

    /**
     * Multiplies the polynomial by an <code>IntegerPolynomial</code>, taking the indices mod N
     */
    IntegerPolynomial mult(IntegerPolynomial poly2);

    int[] getOnes();

    int[] getNegOnes();

    /**
     * Returns the maximum number of coefficients the polynomial can have
     */
    int size();

    void clear();
}
