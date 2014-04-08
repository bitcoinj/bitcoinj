package org.bouncycastle.pqc.math.ntru.euclid;

/**
 * Extended Euclidean Algorithm in <code>int</code>s
 */
public class IntEuclidean
{
    public int x, y, gcd;

    private IntEuclidean()
    {
    }

    /**
     * Runs the EEA on two <code>int</code>s<br>
     * Implemented from pseudocode on <a href="http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm">Wikipedia</a>.
     *
     * @param a
     * @param b
     * @return a <code>IntEuclidean</code> object that contains the result in the variables <code>x</code>, <code>y</code>, and <code>gcd</code>
     */
    public static IntEuclidean calculate(int a, int b)
    {
        int x = 0;
        int lastx = 1;
        int y = 1;
        int lasty = 0;
        while (b != 0)
        {
            int quotient = a / b;

            int temp = a;
            a = b;
            b = temp % b;

            temp = x;
            x = lastx - quotient * x;
            lastx = temp;

            temp = y;
            y = lasty - quotient * y;
            lasty = temp;
        }

        IntEuclidean result = new IntEuclidean();
        result.x = lastx;
        result.y = lasty;
        result.gcd = a;
        return result;
    }
}