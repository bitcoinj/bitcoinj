package org.bouncycastle.pqc.math.linearalgebra;


/**
 * This class implements vectors over the finite field
 * <tt>GF(2<sup>m</sup>)</tt> for small <tt>m</tt> (i.e.,
 * <tt>1&lt;m&lt;32</tt>). It extends the abstract class {@link Vector}.
 */
public class GF2mVector
    extends Vector
{

    /**
     * the finite field this vector is defined over
     */
    private GF2mField field;

    /**
     * the element array
     */
    private int[] vector;

    /**
     * creates the vector over GF(2^m) of given length and with elements from
     * array v (beginning at the first bit)
     *
     * @param field finite field
     * @param v     array with elements of vector
     */
    public GF2mVector(GF2mField field, byte[] v)
    {
        this.field = new GF2mField(field);

        // decode vector
        int d = 8;
        int count = 1;
        while (field.getDegree() > d)
        {
            count++;
            d += 8;
        }

        if ((v.length % count) != 0)
        {
            throw new IllegalArgumentException(
                "Byte array is not an encoded vector over the given finite field.");
        }

        length = v.length / count;
        vector = new int[length];
        count = 0;
        for (int i = 0; i < vector.length; i++)
        {
            for (int j = 0; j < d; j += 8)
            {
                vector[i] |= (v[count++] & 0xff) << j;
            }
            if (!field.isElementOfThisField(vector[i]))
            {
                throw new IllegalArgumentException(
                    "Byte array is not an encoded vector over the given finite field.");
            }
        }
    }

    /**
     * Create a new vector over <tt>GF(2<sup>m</sup>)</tt> of the given
     * length and element array.
     *
     * @param field  the finite field <tt>GF(2<sup>m</sup>)</tt>
     * @param vector the element array
     */
    public GF2mVector(GF2mField field, int[] vector)
    {
        this.field = field;
        length = vector.length;
        for (int i = vector.length - 1; i >= 0; i--)
        {
            if (!field.isElementOfThisField(vector[i]))
            {
                throw new ArithmeticException(
                    "Element array is not specified over the given finite field.");
            }
        }
        this.vector = IntUtils.clone(vector);
    }

    /**
     * Copy constructor.
     *
     * @param other another {@link GF2mVector}
     */
    public GF2mVector(GF2mVector other)
    {
        field = new GF2mField(other.field);
        length = other.length;
        vector = IntUtils.clone(other.vector);
    }

    /**
     * @return the finite field this vector is defined over
     */
    public GF2mField getField()
    {
        return field;
    }

    /**
     * @return int[] form of this vector
     */
    public int[] getIntArrayForm()
    {
        return IntUtils.clone(vector);
    }

    /**
     * @return a byte array encoding of this vector
     */
    public byte[] getEncoded()
    {
        int d = 8;
        int count = 1;
        while (field.getDegree() > d)
        {
            count++;
            d += 8;
        }

        byte[] res = new byte[vector.length * count];
        count = 0;
        for (int i = 0; i < vector.length; i++)
        {
            for (int j = 0; j < d; j += 8)
            {
                res[count++] = (byte)(vector[i] >>> j);
            }
        }

        return res;
    }

    /**
     * @return whether this is the zero vector (i.e., all elements are zero)
     */
    public boolean isZero()
    {
        for (int i = vector.length - 1; i >= 0; i--)
        {
            if (vector[i] != 0)
            {
                return false;
            }
        }
        return true;
    }

    /**
     * Add another vector to this vector. Method is not yet implemented.
     *
     * @param addend the other vector
     * @return <tt>this + addend</tt>
     * @throws ArithmeticException if the other vector is not defined over the same field as
     * this vector.
     * <p>
     * TODO: implement this method
     */
    public Vector add(Vector addend)
    {
        throw new RuntimeException("not implemented");
    }

    /**
     * Multiply this vector with a permutation.
     *
     * @param p the permutation
     * @return <tt>this*p = p*this</tt>
     */
    public Vector multiply(Permutation p)
    {
        int[] pVec = p.getVector();
        if (length != pVec.length)
        {
            throw new ArithmeticException(
                "permutation size and vector size mismatch");
        }

        int[] result = new int[length];
        for (int i = 0; i < pVec.length; i++)
        {
            result[i] = vector[pVec[i]];
        }

        return new GF2mVector(field, result);
    }

    /**
     * Compare this vector with another object.
     *
     * @param other the other object
     * @return the result of the comparison
     */
    public boolean equals(Object other)
    {

        if (!(other instanceof GF2mVector))
        {
            return false;
        }
        GF2mVector otherVec = (GF2mVector)other;

        if (!field.equals(otherVec.field))
        {
            return false;
        }

        return IntUtils.equals(vector, otherVec.vector);
    }

    /**
     * @return the hash code of this vector
     */
    public int hashCode()
    {
        int hash = this.field.hashCode();
        hash = hash * 31 + vector.hashCode();
        return hash;
    }

    /**
     * @return a human readable form of this vector
     */
    public String toString()
    {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < vector.length; i++)
        {
            for (int j = 0; j < field.getDegree(); j++)
            {
                int r = j & 0x1f;
                int bitMask = 1 << r;
                int coeff = vector[i] & bitMask;
                if (coeff != 0)
                {
                    buf.append('1');
                }
                else
                {
                    buf.append('0');
                }
            }
            buf.append(' ');
        }
        return buf.toString();
    }

}
