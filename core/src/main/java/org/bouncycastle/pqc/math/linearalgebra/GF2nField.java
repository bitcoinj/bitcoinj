package org.bouncycastle.pqc.math.linearalgebra;


import java.util.Vector;


/**
 * This abstract class defines the finite field <i>GF(2<sup>n</sup>)</i>. It
 * holds the extension degree <i>n</i>, the characteristic, the irreducible
 * fieldpolynomial and conversion matrices. GF2nField is implemented by the
 * classes GF2nPolynomialField and GF2nONBField.
 *
 * @see GF2nONBField
 * @see GF2nPolynomialField
 */
public abstract class GF2nField
{

    /**
     * the degree of this field
     */
    protected int mDegree;

    /**
     * the irreducible fieldPolynomial stored in normal order (also for ONB)
     */
    protected GF2Polynomial fieldPolynomial;

    /**
     * holds a list of GF2nFields to which elements have been converted and thus
     * a COB-Matrix exists
     */
    protected Vector fields;

    /**
     * the COB matrices
     */
    protected Vector matrices;

    /**
     * Returns the degree <i>n</i> of this field.
     *
     * @return the degree <i>n</i> of this field
     */
    public final int getDegree()
    {
        return mDegree;
    }

    /**
     * Returns the fieldpolynomial as a new Bitstring.
     *
     * @return a copy of the fieldpolynomial as a new Bitstring
     */
    public final GF2Polynomial getFieldPolynomial()
    {
        if (fieldPolynomial == null)
        {
            computeFieldPolynomial();
        }
        return new GF2Polynomial(fieldPolynomial);
    }

    /**
     * Decides whether the given object <tt>other</tt> is the same as this
     * field.
     *
     * @param other another object
     * @return (this == other)
     */
    public final boolean equals(Object other)
    {
        if (other == null || !(other instanceof GF2nField))
        {
            return false;
        }

        GF2nField otherField = (GF2nField)other;

        if (otherField.mDegree != mDegree)
        {
            return false;
        }
        if (!fieldPolynomial.equals(otherField.fieldPolynomial))
        {
            return false;
        }
        if ((this instanceof GF2nPolynomialField)
            && !(otherField instanceof GF2nPolynomialField))
        {
            return false;
        }
        if ((this instanceof GF2nONBField)
            && !(otherField instanceof GF2nONBField))
        {
            return false;
        }
        return true;
    }

    /**
     * @return the hash code of this field
     */
    public int hashCode()
    {
        return mDegree + fieldPolynomial.hashCode();
    }

    /**
     * Computes a random root from the given irreducible fieldpolynomial
     * according to IEEE 1363 algorithm A.5.6. This cal take very long for big
     * degrees.
     *
     * @param B0FieldPolynomial the fieldpolynomial if the other basis as a Bitstring
     * @return a random root of BOFieldPolynomial in representation according to
     *         this field
     * @see "P1363 A.5.6, p103f"
     */
    protected abstract GF2nElement getRandomRoot(GF2Polynomial B0FieldPolynomial);

    /**
     * Computes the change-of-basis matrix for basis conversion according to
     * 1363. The result is stored in the lists fields and matrices.
     *
     * @param B1 the GF2nField to convert to
     * @see "P1363 A.7.3, p111ff"
     */
    protected abstract void computeCOBMatrix(GF2nField B1);

    /**
     * Computes the fieldpolynomial. This can take a long time for big degrees.
     */
    protected abstract void computeFieldPolynomial();

    /**
     * Inverts the given matrix represented as bitstrings.
     *
     * @param matrix the matrix to invert as a Bitstring[]
     * @return matrix^(-1)
     */
    protected final GF2Polynomial[] invertMatrix(GF2Polynomial[] matrix)
    {
        GF2Polynomial[] a = new GF2Polynomial[matrix.length];
        GF2Polynomial[] inv = new GF2Polynomial[matrix.length];
        GF2Polynomial dummy;
        int i, j;
        // initialize a as a copy of matrix and inv as E(inheitsmatrix)
        for (i = 0; i < mDegree; i++)
        {
            try
            {
                a[i] = new GF2Polynomial(matrix[i]);
                inv[i] = new GF2Polynomial(mDegree);
                inv[i].setBit(mDegree - 1 - i);
            }
            catch (RuntimeException BDNEExc)
            {
                BDNEExc.printStackTrace();
            }
        }
        // construct triangle matrix so that for each a[i] the first i bits are
        // zero
        for (i = 0; i < mDegree - 1; i++)
        {
            // find column where bit i is set
            j = i;
            while ((j < mDegree) && !a[j].testBit(mDegree - 1 - i))
            {
                j++;
            }
            if (j >= mDegree)
            {
                throw new RuntimeException(
                    "GF2nField.invertMatrix: Matrix cannot be inverted!");
            }
            if (i != j)
            { // swap a[i]/a[j] and inv[i]/inv[j]
                dummy = a[i];
                a[i] = a[j];
                a[j] = dummy;
                dummy = inv[i];
                inv[i] = inv[j];
                inv[j] = dummy;
            }
            for (j = i + 1; j < mDegree; j++)
            { // add column i to all columns>i
                // having their i-th bit set
                if (a[j].testBit(mDegree - 1 - i))
                {
                    a[j].addToThis(a[i]);
                    inv[j].addToThis(inv[i]);
                }
            }
        }
        // construct Einheitsmatrix from a
        for (i = mDegree - 1; i > 0; i--)
        {
            for (j = i - 1; j >= 0; j--)
            { // eliminate the i-th bit in all
                // columns < i
                if (a[j].testBit(mDegree - 1 - i))
                {
                    a[j].addToThis(a[i]);
                    inv[j].addToThis(inv[i]);
                }
            }
        }
        return inv;
    }

    /**
     * Converts the given element in representation according to this field to a
     * new element in representation according to B1 using the change-of-basis
     * matrix calculated by computeCOBMatrix.
     *
     * @param elem  the GF2nElement to convert
     * @param basis the basis to convert <tt>elem</tt> to
     * @return <tt>elem</tt> converted to a new element representation
     *         according to <tt>basis</tt>
     * @throws DifferentFieldsException if <tt>elem</tt> cannot be converted according to
     * <tt>basis</tt>.
     * @see GF2nField#computeCOBMatrix
     * @see GF2nField#getRandomRoot
     * @see GF2nPolynomial
     * @see "P1363 A.7 p109ff"
     */
    public final GF2nElement convert(GF2nElement elem, GF2nField basis)
        throws RuntimeException
    {
        if (basis == this)
        {
            return (GF2nElement)elem.clone();
        }
        if (fieldPolynomial.equals(basis.fieldPolynomial))
        {
            return (GF2nElement)elem.clone();
        }
        if (mDegree != basis.mDegree)
        {
            throw new RuntimeException("GF2nField.convert: B1 has a"
                + " different degree and thus cannot be coverted to!");
        }

        int i;
        GF2Polynomial[] COBMatrix;
        i = fields.indexOf(basis);
        if (i == -1)
        {
            computeCOBMatrix(basis);
            i = fields.indexOf(basis);
        }
        COBMatrix = (GF2Polynomial[])matrices.elementAt(i);

        GF2nElement elemCopy = (GF2nElement)elem.clone();
        if (elemCopy instanceof GF2nONBElement)
        {
            // remember: ONB treats its bits in reverse order
            ((GF2nONBElement)elemCopy).reverseOrder();
        }
        GF2Polynomial bs = new GF2Polynomial(mDegree, elemCopy.toFlexiBigInt());
        bs.expandN(mDegree);
        GF2Polynomial result = new GF2Polynomial(mDegree);
        for (i = 0; i < mDegree; i++)
        {
            if (bs.vectorMult(COBMatrix[i]))
            {
                result.setBit(mDegree - 1 - i);
            }
        }
        if (basis instanceof GF2nPolynomialField)
        {
            return new GF2nPolynomialElement((GF2nPolynomialField)basis,
                result);
        }
        else if (basis instanceof GF2nONBField)
        {
            GF2nONBElement res = new GF2nONBElement((GF2nONBField)basis,
                result.toFlexiBigInt());
            // TODO Remember: ONB treats its Bits in reverse order !!!
            res.reverseOrder();
            return res;
        }
        else
        {
            throw new RuntimeException(
                "GF2nField.convert: B1 must be an instance of "
                    + "GF2nPolynomialField or GF2nONBField!");
        }

    }

}
