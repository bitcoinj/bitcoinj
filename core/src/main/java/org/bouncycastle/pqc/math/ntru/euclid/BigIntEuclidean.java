package org.bouncycastle.pqc.math.ntru.euclid;

import java.math.BigInteger;

/**
 * Extended Euclidean Algorithm in <code>BigInteger</code>s
 */
public class BigIntEuclidean
{
    public BigInteger x, y, gcd;

    private BigIntEuclidean()
    {
    }

    /**
     * Runs the EEA on two <code>BigInteger</code>s<br>
     * Implemented from pseudocode on <a href="http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm">Wikipedia</a>.
     *
     * @param a
     * @param b
     * @return a <code>BigIntEuclidean</code> object that contains the result in the variables <code>x</code>, <code>y</code>, and <code>gcd</code>
     */
    public static BigIntEuclidean calculate(BigInteger a, BigInteger b)
    {
        BigInteger x = BigInteger.ZERO;
        BigInteger lastx = BigInteger.ONE;
        BigInteger y = BigInteger.ONE;
        BigInteger lasty = BigInteger.ZERO;
        while (!b.equals(BigInteger.ZERO))
        {
            BigInteger[] quotientAndRemainder = a.divideAndRemainder(b);
            BigInteger quotient = quotientAndRemainder[0];

            BigInteger temp = a;
            a = b;
            b = quotientAndRemainder[1];

            temp = x;
            x = lastx.subtract(quotient.multiply(x));
            lastx = temp;

            temp = y;
            y = lasty.subtract(quotient.multiply(y));
            lasty = temp;
        }

        BigIntEuclidean result = new BigIntEuclidean();
        result.x = lastx;
        result.y = lasty;
        result.gcd = a;
        return result;
    }
}