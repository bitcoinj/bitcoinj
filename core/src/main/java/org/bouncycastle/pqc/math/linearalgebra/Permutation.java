package org.bouncycastle.pqc.math.linearalgebra;

import java.security.SecureRandom;

/**
 * This class implements permutations of the set {0,1,...,n-1} for some given n
 * &gt; 0, i.e., ordered sequences containing each number <tt>m</tt> (<tt>0 &lt;=
 * m &lt; n</tt>)
 * once and only once.
 */
public class Permutation
{

    /**
     * perm holds the elements of the permutation vector, i.e. <tt>[perm(0),
     * perm(1), ..., perm(n-1)]</tt>
     */
    private int[] perm;

    /**
     * Create the identity permutation of the given size.
     *
     * @param n the size of the permutation
     */
    public Permutation(int n)
    {
        if (n <= 0)
        {
            throw new IllegalArgumentException("invalid length");
        }

        perm = new int[n];
        for (int i = n - 1; i >= 0; i--)
        {
            perm[i] = i;
        }
    }

    /**
     * Create a permutation using the given permutation vector.
     *
     * @param perm the permutation vector
     */
    public Permutation(int[] perm)
    {
        if (!isPermutation(perm))
        {
            throw new IllegalArgumentException(
                "array is not a permutation vector");
        }

        this.perm = IntUtils.clone(perm);
    }

    /**
     * Create a permutation from an encoded permutation.
     *
     * @param enc the encoded permutation
     */
    public Permutation(byte[] enc)
    {
        if (enc.length <= 4)
        {
            throw new IllegalArgumentException("invalid encoding");
        }

        int n = LittleEndianConversions.OS2IP(enc, 0);
        int size = IntegerFunctions.ceilLog256(n - 1);

        if (enc.length != 4 + n * size)
        {
            throw new IllegalArgumentException("invalid encoding");
        }

        perm = new int[n];
        for (int i = 0; i < n; i++)
        {
            perm[i] = LittleEndianConversions.OS2IP(enc, 4 + i * size, size);
        }

        if (!isPermutation(perm))
        {
            throw new IllegalArgumentException("invalid encoding");
        }

    }

    /**
     * Create a random permutation of the given size.
     *
     * @param n  the size of the permutation
     * @param sr the source of randomness
     */
    public Permutation(int n, SecureRandom sr)
    {
        if (n <= 0)
        {
            throw new IllegalArgumentException("invalid length");
        }

        perm = new int[n];

        int[] help = new int[n];
        for (int i = 0; i < n; i++)
        {
            help[i] = i;
        }

        int k = n;
        for (int j = 0; j < n; j++)
        {
            int i = RandUtils.nextInt(sr, k);
            k--;
            perm[j] = help[i];
            help[i] = help[k];
        }
    }

    /**
     * Encode this permutation as byte array.
     *
     * @return the encoded permutation
     */
    public byte[] getEncoded()
    {
        int n = perm.length;
        int size = IntegerFunctions.ceilLog256(n - 1);
        byte[] result = new byte[4 + n * size];
        LittleEndianConversions.I2OSP(n, result, 0);
        for (int i = 0; i < n; i++)
        {
            LittleEndianConversions.I2OSP(perm[i], result, 4 + i * size, size);
        }
        return result;
    }

    /**
     * @return the permutation vector <tt>(perm(0),perm(1),...,perm(n-1))</tt>
     */
    public int[] getVector()
    {
        return IntUtils.clone(perm);
    }

    /**
     * Compute the inverse permutation <tt>P<sup>-1</sup></tt>.
     *
     * @return <tt>this<sup>-1</sup></tt>
     */
    public Permutation computeInverse()
    {
        Permutation result = new Permutation(perm.length);
        for (int i = perm.length - 1; i >= 0; i--)
        {
            result.perm[perm[i]] = i;
        }
        return result;
    }

    /**
     * Compute the product of this permutation and another permutation.
     *
     * @param p the other permutation
     * @return <tt>this * p</tt>
     */
    public Permutation rightMultiply(Permutation p)
    {
        if (p.perm.length != perm.length)
        {
            throw new IllegalArgumentException("length mismatch");
        }
        Permutation result = new Permutation(perm.length);
        for (int i = perm.length - 1; i >= 0; i--)
        {
            result.perm[i] = perm[p.perm[i]];
        }
        return result;
    }

    /**
     * checks if given object is equal to this permutation.
     * <p>
     * The method returns false whenever the given object is not permutation.
     *
     * @param other -
     *              permutation
     * @return true or false
     */
    public boolean equals(Object other)
    {

        if (!(other instanceof Permutation))
        {
            return false;
        }
        Permutation otherPerm = (Permutation)other;

        return IntUtils.equals(perm, otherPerm.perm);
    }

    /**
     * @return a human readable form of the permutation
     */
    public String toString()
    {
        String result = "[" + perm[0];
        for (int i = 1; i < perm.length; i++)
        {
            result += ", " + perm[i];
        }
        result += "]";
        return result;
    }

    /**
     * @return the hash code of this permutation
     */
    public int hashCode()
    {
        return perm.hashCode();
    }

    /**
     * Check that the given array corresponds to a permutation of the set
     * <tt>{0, 1, ..., n-1}</tt>.
     *
     * @param perm permutation vector
     * @return true if perm represents an n-permutation and false otherwise
     */
    private boolean isPermutation(int[] perm)
    {
        int n = perm.length;
        boolean[] onlyOnce = new boolean[n];

        for (int i = 0; i < n; i++)
        {
            if ((perm[i] < 0) || (perm[i] >= n) || onlyOnce[perm[i]])
            {
                return false;
            }
            onlyOnce[perm[i]] = true;
        }

        return true;
    }

}
