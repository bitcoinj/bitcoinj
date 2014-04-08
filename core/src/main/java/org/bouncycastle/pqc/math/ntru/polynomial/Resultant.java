package org.bouncycastle.pqc.math.ntru.polynomial;

import java.math.BigInteger;

/**
 * Contains a resultant and a polynomial <code>rho</code> such that
 * <code>res = rho*this + t*(x^n-1) for some integer t</code>.
 *
 * @see IntegerPolynomial#resultant()
 * @see IntegerPolynomial#resultant(int)
 */
public class Resultant
{
    /**
     * A polynomial such that <code>res = rho*this + t*(x^n-1) for some integer t</code>
     */
    public BigIntPolynomial rho;
    /**
     * Resultant of a polynomial with <code>x^n-1</code>
     */
    public BigInteger res;

    Resultant(BigIntPolynomial rho, BigInteger res)
    {
        this.rho = rho;
        this.res = res;
    }
}
