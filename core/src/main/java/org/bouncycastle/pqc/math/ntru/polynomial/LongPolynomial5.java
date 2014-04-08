package org.bouncycastle.pqc.math.ntru.polynomial;

import org.bouncycastle.util.Arrays;

/**
 * A polynomial class that combines five coefficients into one <code>long</code> value for
 * faster multiplication by a ternary polynomial.<br>
 * Coefficients can be between 0 and 2047 and are stored in bits 0..11, 12..23, ..., 48..59 of a <code>long</code> number.
 */
public class LongPolynomial5
{
    private long[] coeffs;   // groups of 5 coefficients
    private int numCoeffs;

    /**
     * Constructs a <code>LongPolynomial5</code> from a <code>IntegerPolynomial</code>. The two polynomials are independent of each other.
     *
     * @param p the original polynomial. Coefficients must be between 0 and 2047.
     */
    public LongPolynomial5(IntegerPolynomial p)
    {
        numCoeffs = p.coeffs.length;

        coeffs = new long[(numCoeffs + 4) / 5];
        int cIdx = 0;
        int shift = 0;
        for (int i = 0; i < numCoeffs; i++)
        {
            coeffs[cIdx] |= ((long)p.coeffs[i]) << shift;
            shift += 12;
            if (shift >= 60)
            {
                shift = 0;
                cIdx++;
            }
        }
    }

    private LongPolynomial5(long[] coeffs, int numCoeffs)
    {
        this.coeffs = coeffs;
        this.numCoeffs = numCoeffs;
    }

    /**
     * Multiplies the polynomial with a <code>TernaryPolynomial</code>, taking the indices mod N and the values mod 2048.
     */
    public LongPolynomial5 mult(TernaryPolynomial poly2)
    {
        long[][] prod = new long[5][coeffs.length + (poly2.size() + 4) / 5 - 1];   // intermediate results, the subarrays are shifted by 0,...,4 coefficients

        // multiply ones
        int[] ones = poly2.getOnes();
        for (int idx = 0; idx != ones.length; idx++)
        {
            int pIdx = ones[idx];
            int cIdx = pIdx / 5;
            int m = pIdx - cIdx * 5;   // m = pIdx % 5
            for (int i = 0; i < coeffs.length; i++)
            {
                prod[m][cIdx] = (prod[m][cIdx] + coeffs[i]) & 0x7FF7FF7FF7FF7FFL;
                cIdx++;
            }
        }

        // multiply negative ones
        int[] negOnes = poly2.getNegOnes();
        for (int idx = 0; idx != negOnes.length; idx++)
        {
            int pIdx = negOnes[idx];
            int cIdx = pIdx / 5;
            int m = pIdx - cIdx * 5;   // m = pIdx % 5
            for (int i = 0; i < coeffs.length; i++)
            {
                prod[m][cIdx] = (0x800800800800800L + prod[m][cIdx] - coeffs[i]) & 0x7FF7FF7FF7FF7FFL;
                cIdx++;
            }
        }

        // combine shifted coefficients (5 arrays) into a single array of length prod[*].length+1
        long[] cCoeffs = Arrays.copyOf(prod[0], prod[0].length + 1);
        for (int m = 1; m <= 4; m++)
        {
            int shift = m * 12;
            int shift60 = 60 - shift;
            long mask = (1L << shift60) - 1;
            int pLen = prod[m].length;
            for (int i = 0; i < pLen; i++)
            {
                long upper, lower;
                upper = prod[m][i] >> shift60;
                lower = prod[m][i] & mask;

                cCoeffs[i] = (cCoeffs[i] + (lower << shift)) & 0x7FF7FF7FF7FF7FFL;
                int nextIdx = i + 1;
                cCoeffs[nextIdx] = (cCoeffs[nextIdx] + upper) & 0x7FF7FF7FF7FF7FFL;
            }
        }

        // reduce indices of cCoeffs modulo numCoeffs
        int shift = 12 * (numCoeffs % 5);
        for (int cIdx = coeffs.length - 1; cIdx < cCoeffs.length; cIdx++)
        {
            long iCoeff;   // coefficient to shift into the [0..numCoeffs-1] range
            int newIdx;
            if (cIdx == coeffs.length - 1)
            {
                iCoeff = numCoeffs == 5 ? 0 : cCoeffs[cIdx] >> shift;
                newIdx = 0;
            }
            else
            {
                iCoeff = cCoeffs[cIdx];
                newIdx = cIdx * 5 - numCoeffs;
            }

            int base = newIdx / 5;
            int m = newIdx - base * 5;   // m = newIdx % 5
            long lower = iCoeff << (12 * m);
            long upper = iCoeff >> (12 * (5 - m));
            cCoeffs[base] = (cCoeffs[base] + lower) & 0x7FF7FF7FF7FF7FFL;
            int base1 = base + 1;
            if (base1 < coeffs.length)
            {
                cCoeffs[base1] = (cCoeffs[base1] + upper) & 0x7FF7FF7FF7FF7FFL;
            }
        }

        return new LongPolynomial5(cCoeffs, numCoeffs);
    }

    public IntegerPolynomial toIntegerPolynomial()
    {
        int[] intCoeffs = new int[numCoeffs];
        int cIdx = 0;
        int shift = 0;
        for (int i = 0; i < numCoeffs; i++)
        {
            intCoeffs[i] = (int)((coeffs[cIdx] >> shift) & 2047);
            shift += 12;
            if (shift >= 60)
            {
                shift = 0;
                cIdx++;
            }
        }
        return new IntegerPolynomial(intCoeffs);
    }
}
