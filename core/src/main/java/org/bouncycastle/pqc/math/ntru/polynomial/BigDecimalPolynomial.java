package org.bouncycastle.pqc.math.ntru.polynomial;

import java.math.BigDecimal;

/**
 * A polynomial with {@link BigDecimal} coefficients.
 * Some methods (like <code>add</code>) change the polynomial, others (like <code>mult</code>) do
 * not but return the result as a new polynomial.
 */
public class BigDecimalPolynomial
{
    private static final BigDecimal ZERO = new BigDecimal("0");
    private static final BigDecimal ONE_HALF = new BigDecimal("0.5");

    BigDecimal[] coeffs;

    /**
     * Constructs a new polynomial with <code>N</code> coefficients initialized to 0.
     *
     * @param N the number of coefficients
     */
    BigDecimalPolynomial(int N)
    {
        coeffs = new BigDecimal[N];
        for (int i = 0; i < N; i++)
        {
            coeffs[i] = ZERO;
        }
    }

    /**
     * Constructs a new polynomial with a given set of coefficients.
     *
     * @param coeffs the coefficients
     */
    BigDecimalPolynomial(BigDecimal[] coeffs)
    {
        this.coeffs = coeffs;
    }

    /**
     * Constructs a <code>BigDecimalPolynomial</code> from a <code>BigIntPolynomial</code>. The two polynomials are independent of each other.
     *
     * @param p the original polynomial
     */
    public BigDecimalPolynomial(BigIntPolynomial p)
    {
        int N = p.coeffs.length;
        coeffs = new BigDecimal[N];
        for (int i = 0; i < N; i++)
        {
            coeffs[i] = new BigDecimal(p.coeffs[i]);
        }
    }

    /**
     * Divides all coefficients by 2.
     */
    public void halve()
    {
        for (int i = 0; i < coeffs.length; i++)
        {
            coeffs[i] = coeffs[i].multiply(ONE_HALF);
        }
    }

    /**
     * Multiplies the polynomial by another. Does not change this polynomial
     * but returns the result as a new polynomial.
     *
     * @param poly2 the polynomial to multiply by
     * @return a new polynomial
     */
    public BigDecimalPolynomial mult(BigIntPolynomial poly2)
    {
        return mult(new BigDecimalPolynomial(poly2));
    }

    /**
     * Multiplies the polynomial by another, taking the indices mod N. Does not
     * change this polynomial but returns the result as a new polynomial.
     *
     * @param poly2 the polynomial to multiply by
     * @return a new polynomial
     */
    public BigDecimalPolynomial mult(BigDecimalPolynomial poly2)
    {
        int N = coeffs.length;
        if (poly2.coeffs.length != N)
        {
            throw new IllegalArgumentException("Number of coefficients must be the same");
        }

        BigDecimalPolynomial c = multRecursive(poly2);

        if (c.coeffs.length > N)
        {
            for (int k = N; k < c.coeffs.length; k++)
            {
                c.coeffs[k - N] = c.coeffs[k - N].add(c.coeffs[k]);
            }
            c.coeffs = copyOf(c.coeffs, N);
        }
        return c;
    }

    /**
     * Karazuba multiplication
     */
    private BigDecimalPolynomial multRecursive(BigDecimalPolynomial poly2)
    {
        BigDecimal[] a = coeffs;
        BigDecimal[] b = poly2.coeffs;

        int n = poly2.coeffs.length;
        if (n <= 1)
        {
            BigDecimal[] c = coeffs.clone();
            for (int i = 0; i < coeffs.length; i++)
            {
                c[i] = c[i].multiply(poly2.coeffs[0]);
            }
            return new BigDecimalPolynomial(c);
        }
        else
        {
            int n1 = n / 2;

            BigDecimalPolynomial a1 = new BigDecimalPolynomial(copyOf(a, n1));
            BigDecimalPolynomial a2 = new BigDecimalPolynomial(copyOfRange(a, n1, n));
            BigDecimalPolynomial b1 = new BigDecimalPolynomial(copyOf(b, n1));
            BigDecimalPolynomial b2 = new BigDecimalPolynomial(copyOfRange(b, n1, n));

            BigDecimalPolynomial A = (BigDecimalPolynomial)a1.clone();
            A.add(a2);
            BigDecimalPolynomial B = (BigDecimalPolynomial)b1.clone();
            B.add(b2);

            BigDecimalPolynomial c1 = a1.multRecursive(b1);
            BigDecimalPolynomial c2 = a2.multRecursive(b2);
            BigDecimalPolynomial c3 = A.multRecursive(B);
            c3.sub(c1);
            c3.sub(c2);

            BigDecimalPolynomial c = new BigDecimalPolynomial(2 * n - 1);
            for (int i = 0; i < c1.coeffs.length; i++)
            {
                c.coeffs[i] = c1.coeffs[i];
            }
            for (int i = 0; i < c3.coeffs.length; i++)
            {
                c.coeffs[n1 + i] = c.coeffs[n1 + i].add(c3.coeffs[i]);
            }
            for (int i = 0; i < c2.coeffs.length; i++)
            {
                c.coeffs[2 * n1 + i] = c.coeffs[2 * n1 + i].add(c2.coeffs[i]);
            }
            return c;
        }
    }

    /**
     * Adds another polynomial which can have a different number of coefficients.
     *
     * @param b another polynomial
     */
    public void add(BigDecimalPolynomial b)
    {
        if (b.coeffs.length > coeffs.length)
        {
            int N = coeffs.length;
            coeffs = copyOf(coeffs, b.coeffs.length);
            for (int i = N; i < coeffs.length; i++)
            {
                coeffs[i] = ZERO;
            }
        }
        for (int i = 0; i < b.coeffs.length; i++)
        {
            coeffs[i] = coeffs[i].add(b.coeffs[i]);
        }
    }

    /**
     * Subtracts another polynomial which can have a different number of coefficients.
     *
     * @param b
     */
    void sub(BigDecimalPolynomial b)
    {
        if (b.coeffs.length > coeffs.length)
        {
            int N = coeffs.length;
            coeffs = copyOf(coeffs, b.coeffs.length);
            for (int i = N; i < coeffs.length; i++)
            {
                coeffs[i] = ZERO;
            }
        }
        for (int i = 0; i < b.coeffs.length; i++)
        {
            coeffs[i] = coeffs[i].subtract(b.coeffs[i]);
        }
    }

    /**
     * Rounds all coefficients to the nearest integer.
     *
     * @return a new polynomial with <code>BigInteger</code> coefficients
     */
    public BigIntPolynomial round()
    {
        int N = coeffs.length;
        BigIntPolynomial p = new BigIntPolynomial(N);
        for (int i = 0; i < N; i++)
        {
            p.coeffs[i] = coeffs[i].setScale(0, BigDecimal.ROUND_HALF_EVEN).toBigInteger();
        }
        return p;
    }

    /**
     * Makes a copy of the polynomial that is independent of the original.
     */
    public Object clone()
    {
        return new BigDecimalPolynomial(coeffs.clone());
    }

    private BigDecimal[] copyOf(BigDecimal[] a, int length)
    {
        BigDecimal[] tmp = new BigDecimal[length];

        System.arraycopy(a, 0, tmp, 0, a.length < length ? a.length : length);

        return tmp;
    }

    private BigDecimal[] copyOfRange(BigDecimal[] a, int from, int to)
    {
        int          newLength = to - from;
        BigDecimal[] tmp = new BigDecimal[to - from];

        System.arraycopy(a, from, tmp, 0, (a.length - from) < newLength ? (a.length - from) : newLength);

        return tmp;
    }

    public BigDecimal[] getCoeffs()
    {
        BigDecimal[] tmp = new BigDecimal[coeffs.length];

        System.arraycopy(coeffs, 0, tmp, 0, coeffs.length);

        return tmp;
    }

}
