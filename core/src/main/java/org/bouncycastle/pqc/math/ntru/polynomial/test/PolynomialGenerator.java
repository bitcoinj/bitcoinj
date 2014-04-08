package org.bouncycastle.pqc.math.ntru.polynomial.test;

import java.util.Random;

import org.bouncycastle.pqc.math.ntru.polynomial.IntegerPolynomial;

public class PolynomialGenerator
{
    /**
     * Creates a random polynomial with <code>N</code> coefficients
     * between <code>0</code> and <code>q-1</code>.
     *
     * @param N length of the polynomial
     * @param q coefficients will all be below this number
     * @return a random polynomial
     */
    public static IntegerPolynomial generateRandom(int N, int q)
    {
        Random rng = new Random();
        int[] coeffs = new int[N];
        for (int i = 0; i < N; i++)
        {
            coeffs[i] = rng.nextInt(q);
        }
        return new IntegerPolynomial(coeffs);
    }
}