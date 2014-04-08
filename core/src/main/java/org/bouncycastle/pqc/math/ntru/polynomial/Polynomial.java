package org.bouncycastle.pqc.math.ntru.polynomial;

public interface Polynomial
{

    /**
     * Multiplies the polynomial by an <code>IntegerPolynomial</code>,
     * taking the indices mod <code>N</code>.
     *
     * @param poly2 a polynomial
     * @return the product of the two polynomials
     */
    IntegerPolynomial mult(IntegerPolynomial poly2);

    /**
     * Multiplies the polynomial by an <code>IntegerPolynomial</code>,
     * taking the coefficient values mod <code>modulus</code> and the indices mod <code>N</code>.
     *
     * @param poly2   a polynomial
     * @param modulus a modulus to apply
     * @return the product of the two polynomials
     */
    IntegerPolynomial mult(IntegerPolynomial poly2, int modulus);

    /**
     * Returns a polynomial that is equal to this polynomial (in the sense that {@link #mult(IntegerPolynomial, int)}
     * returns equal <code>IntegerPolynomial</code>s). The new polynomial is guaranteed to be independent of the original.
     *
     * @return a new <code>IntegerPolynomial</code>.
     */
    IntegerPolynomial toIntegerPolynomial();

    /**
     * Multiplies the polynomial by a <code>BigIntPolynomial</code>, taking the indices mod N. Does not
     * change this polynomial but returns the result as a new polynomial.<br>
     * Both polynomials must have the same number of coefficients.
     *
     * @param poly2 the polynomial to multiply by
     * @return a new polynomial
     */
    BigIntPolynomial mult(BigIntPolynomial poly2);
}
