package org.bouncycastle.pqc.math.ntru.util;

import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.pqc.math.ntru.euclid.IntEuclidean;
import org.bouncycastle.pqc.math.ntru.polynomial.DenseTernaryPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.SparseTernaryPolynomial;
import org.bouncycastle.pqc.math.ntru.polynomial.TernaryPolynomial;
import org.bouncycastle.util.Integers;

public class Util
{
    private static volatile boolean IS_64_BITNESS_KNOWN;
    private static volatile boolean IS_64_BIT_JVM;

    /**
     * Calculates the inverse of n mod modulus
     */
    public static int invert(int n, int modulus)
    {
        n %= modulus;
        if (n < 0)
        {
            n += modulus;
        }
        return IntEuclidean.calculate(n, modulus).x;
    }

    /**
     * Calculates a^b mod modulus
     */
    public static int pow(int a, int b, int modulus)
    {
        int p = 1;
        for (int i = 0; i < b; i++)
        {
            p = (p * a) % modulus;
        }
        return p;
    }

    /**
     * Calculates a^b mod modulus
     */
    public static long pow(long a, int b, long modulus)
    {
        long p = 1;
        for (int i = 0; i < b; i++)
        {
            p = (p * a) % modulus;
        }
        return p;
    }

    /**
     * Generates a "sparse" or "dense" polynomial containing numOnes ints equal to 1,
     * numNegOnes int equal to -1, and the rest equal to 0.
     *
     * @param N
     * @param numOnes
     * @param numNegOnes
     * @param sparse     whether to create a {@link SparseTernaryPolynomial} or {@link DenseTernaryPolynomial}
     * @return a ternary polynomial
     */
    public static TernaryPolynomial generateRandomTernary(int N, int numOnes, int numNegOnes, boolean sparse, SecureRandom random)
    {
        if (sparse)
        {
            return SparseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes, random);
        }
        else
        {
            return DenseTernaryPolynomial.generateRandom(N, numOnes, numNegOnes, random);
        }
    }

    /**
     * Generates an array containing numOnes ints equal to 1,
     * numNegOnes int equal to -1, and the rest equal to 0.
     *
     * @param N
     * @param numOnes
     * @param numNegOnes
     * @return an array of integers
     */
    public static int[] generateRandomTernary(int N, int numOnes, int numNegOnes, SecureRandom random)
    {
        Integer one = Integers.valueOf(1);
        Integer minusOne = Integers.valueOf(-1);
        Integer zero = Integers.valueOf(0);

        List list = new ArrayList();
        for (int i = 0; i < numOnes; i++)
        {
            list.add(one);
        }
        for (int i = 0; i < numNegOnes; i++)
        {
            list.add(minusOne);
        }
        while (list.size() < N)
        {
            list.add(zero);
        }

        Collections.shuffle(list, random);

        int[] arr = new int[N];
        for (int i = 0; i < N; i++)
        {
            arr[i] = ((Integer)list.get(i)).intValue();
        }
        return arr;
    }

    /**
     * Takes an educated guess as to whether 64 bits are supported by the JVM.
     *
     * @return <code>true</code> if 64-bit support detected, <code>false</code> otherwise
     */
    public static boolean is64BitJVM()
    {
        if (!IS_64_BITNESS_KNOWN)
        {
            String arch = System.getProperty("os.arch");
            String sunModel = System.getProperty("sun.arch.data.model");
            IS_64_BIT_JVM = "amd64".equals(arch) || "x86_64".equals(arch) || "ppc64".equals(arch) || "64".equals(sunModel);
            IS_64_BITNESS_KNOWN = true;
        }
        return IS_64_BIT_JVM;
    }

    /**
     * Reads a given number of bytes from an <code>InputStream</code>.
     * If there are not enough bytes in the stream, an <code>IOException</code>
     * is thrown.
     *
     * @param is
     * @param length
     * @return an array of length <code>length</code>
     * @throws IOException
     */
    public static byte[] readFullLength(InputStream is, int length)
        throws IOException
    {
        byte[] arr = new byte[length];
        if (is.read(arr) != arr.length)
        {
            throw new IOException("Not enough bytes to read.");
        }
        return arr;
    }
}