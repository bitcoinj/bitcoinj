package org.bouncycastle.pqc.math.linearalgebra;

/**
 * This abstract class defines vectors. It holds the length of vector.
 */
public abstract class Vector
{

    /**
     * the length of this vector
     */
    protected int length;

    /**
     * @return the length of this vector
     */
    public final int getLength()
    {
        return length;
    }

    /**
     * @return this vector as byte array
     */
    public abstract byte[] getEncoded();

    /**
     * Return whether this is the zero vector (i.e., all elements are zero).
     *
     * @return <tt>true</tt> if this is the zero vector, <tt>false</tt>
     *         otherwise
     */
    public abstract boolean isZero();

    /**
     * Add another vector to this vector.
     *
     * @param addend the other vector
     * @return <tt>this + addend</tt>
     */
    public abstract Vector add(Vector addend);

    /**
     * Multiply this vector with a permutation.
     *
     * @param p the permutation
     * @return <tt>this*p = p*this</tt>
     */
    public abstract Vector multiply(Permutation p);

    /**
     * Check if the given object is equal to this vector.
     *
     * @param other vector
     * @return the result of the comparison
     */
    public abstract boolean equals(Object other);

    /**
     * @return the hash code of this vector
     */
    public abstract int hashCode();

    /**
     * @return a human readable form of this vector
     */
    public abstract String toString();

}
