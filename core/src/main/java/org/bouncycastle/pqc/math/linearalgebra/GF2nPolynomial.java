package org.bouncycastle.pqc.math.linearalgebra;


/**
 * This class implements polynomials over GF2nElements.
 *
 * @see GF2nElement
 */

public class GF2nPolynomial
{

    private GF2nElement[] coeff; // keeps the coefficients of this polynomial

    private int size; // the size of this polynomial

    /**
     * Creates a new PolynomialGF2n of size <i>deg</i> and elem as
     * coefficients.
     *
     * @param deg  -
     *             the maximum degree + 1
     * @param elem -
     *             a GF2nElement
     */
    public GF2nPolynomial(int deg, GF2nElement elem)
    {
        size = deg;
        coeff = new GF2nElement[size];
        for (int i = 0; i < size; i++)
        {
            coeff[i] = (GF2nElement)elem.clone();
        }
    }

    /**
     * Creates a new PolynomialGF2n of size <i>deg</i>.
     *
     * @param deg the maximum degree + 1
     */
    private GF2nPolynomial(int deg)
    {
        size = deg;
        coeff = new GF2nElement[size];
    }

    /**
     * Creates a new PolynomialGF2n by cloning the given PolynomialGF2n <i>a</i>.
     *
     * @param a the PolynomialGF2n to clone
     */
    public GF2nPolynomial(GF2nPolynomial a)
    {
        int i;
        coeff = new GF2nElement[a.size];
        size = a.size;
        for (i = 0; i < size; i++)
        {
            coeff[i] = (GF2nElement)a.coeff[i].clone();
        }
    }

    /**
     * Creates a new PolynomialGF2n from the given Bitstring <i>polynomial</i>
     * over the GF2nField <i>B1</i>.
     *
     * @param polynomial the Bitstring to use
     * @param B1         the field
     */
    public GF2nPolynomial(GF2Polynomial polynomial, GF2nField B1)
    {
        size = B1.getDegree() + 1;
        coeff = new GF2nElement[size];
        int i;
        if (B1 instanceof GF2nONBField)
        {
            for (i = 0; i < size; i++)
            {
                if (polynomial.testBit(i))
                {
                    coeff[i] = GF2nONBElement.ONE((GF2nONBField)B1);
                }
                else
                {
                    coeff[i] = GF2nONBElement.ZERO((GF2nONBField)B1);
                }
            }
        }
        else if (B1 instanceof GF2nPolynomialField)
        {
            for (i = 0; i < size; i++)
            {
                if (polynomial.testBit(i))
                {
                    coeff[i] = GF2nPolynomialElement
                        .ONE((GF2nPolynomialField)B1);
                }
                else
                {
                    coeff[i] = GF2nPolynomialElement
                        .ZERO((GF2nPolynomialField)B1);
                }
            }
        }
        else
        {
            throw new IllegalArgumentException(
                "PolynomialGF2n(Bitstring, GF2nField): B1 must be "
                    + "an instance of GF2nONBField or GF2nPolynomialField!");
        }
    }

    public final void assignZeroToElements()
    {
        int i;
        for (i = 0; i < size; i++)
        {
            coeff[i].assignZero();
        }
    }

    /**
     * Returns the size (=maximum degree + 1) of this PolynomialGF2n. This is
     * not the degree, use getDegree instead.
     *
     * @return the size (=maximum degree + 1) of this PolynomialGF2n.
     */
    public final int size()
    {
        return size;
    }

    /**
     * Returns the degree of this PolynomialGF2n.
     *
     * @return the degree of this PolynomialGF2n.
     */
    public final int getDegree()
    {
        int i;
        for (i = size - 1; i >= 0; i--)
        {
            if (!coeff[i].isZero())
            {
                return i;
            }
        }
        return -1;
    }

    /**
     * Enlarges the size of this PolynomialGF2n to <i>k</i> + 1.
     *
     * @param k the new maximum degree
     */
    public final void enlarge(int k)
    {
        if (k <= size)
        {
            return;
        }
        int i;
        GF2nElement[] res = new GF2nElement[k];
        System.arraycopy(coeff, 0, res, 0, size);
        GF2nField f = coeff[0].getField();
        if (coeff[0] instanceof GF2nPolynomialElement)
        {
            for (i = size; i < k; i++)
            {
                res[i] = GF2nPolynomialElement.ZERO((GF2nPolynomialField)f);
            }
        }
        else if (coeff[0] instanceof GF2nONBElement)
        {
            for (i = size; i < k; i++)
            {
                res[i] = GF2nONBElement.ZERO((GF2nONBField)f);
            }
        }
        size = k;
        coeff = res;
    }

    public final void shrink()
    {
        int i = size - 1;
        while (coeff[i].isZero() && (i > 0))
        {
            i--;
        }
        i++;
        if (i < size)
        {
            GF2nElement[] res = new GF2nElement[i];
            System.arraycopy(coeff, 0, res, 0, i);
            coeff = res;
            size = i;
        }
    }

    /**
     * Sets the coefficient at <i>index</i> to <i>elem</i>.
     *
     * @param index the index
     * @param elem  the GF2nElement to store as coefficient <i>index</i>
     */
    public final void set(int index, GF2nElement elem)
    {
        if (!(elem instanceof GF2nPolynomialElement)
            && !(elem instanceof GF2nONBElement))
        {
            throw new IllegalArgumentException(
                "PolynomialGF2n.set f must be an "
                    + "instance of either GF2nPolynomialElement or GF2nONBElement!");
        }
        coeff[index] = (GF2nElement)elem.clone();
    }

    /**
     * Returns the coefficient at <i>index</i>.
     *
     * @param index the index
     * @return the GF2nElement stored as coefficient <i>index</i>
     */
    public final GF2nElement at(int index)
    {
        return coeff[index];
    }

    /**
     * Returns true if all coefficients equal zero.
     *
     * @return true if all coefficients equal zero.
     */
    public final boolean isZero()
    {
        int i;
        for (i = 0; i < size; i++)
        {
            if (coeff[i] != null)
            {
                if (!coeff[i].isZero())
                {
                    return false;
                }
            }
        }
        return true;
    }

    public final boolean equals(Object other)
    {
        if (other == null || !(other instanceof GF2nPolynomial))
        {
            return false;
        }

        GF2nPolynomial otherPol = (GF2nPolynomial)other;

        if (getDegree() != otherPol.getDegree())
        {
            return false;
        }
        int i;
        for (i = 0; i < size; i++)
        {
            if (!coeff[i].equals(otherPol.coeff[i]))
            {
                return false;
            }
        }
        return true;
    }

    /**
     * @return the hash code of this polynomial
     */
    public int hashCode()
    {
        return getDegree() + coeff.hashCode();
    }

    /**
     * Adds the PolynomialGF2n <tt>b</tt> to <tt>this</tt> and returns the
     * result in a new <tt>PolynomialGF2n</tt>.
     *
     * @param b -
     *          the <tt>PolynomialGF2n</tt> to add
     * @return <tt>this + b</tt>
     * @throws DifferentFieldsException if <tt>this</tt> and <tt>b</tt> are not defined over
     * the same field.
     */
    public final GF2nPolynomial add(GF2nPolynomial b)
        throws RuntimeException
    {
        GF2nPolynomial result;
        if (size() >= b.size())
        {
            result = new GF2nPolynomial(size());
            int i;
            for (i = 0; i < b.size(); i++)
            {
                result.coeff[i] = (GF2nElement)coeff[i].add(b.coeff[i]);
            }
            for (; i < size(); i++)
            {
                result.coeff[i] = coeff[i];
            }
        }
        else
        {
            result = new GF2nPolynomial(b.size());
            int i;
            for (i = 0; i < size(); i++)
            {
                result.coeff[i] = (GF2nElement)coeff[i].add(b.coeff[i]);
            }
            for (; i < b.size(); i++)
            {
                result.coeff[i] = b.coeff[i];
            }
        }
        return result;
    }

    /**
     * Multiplies the scalar <i>s</i> to each coefficient of this
     * PolynomialGF2n and returns the result in a new PolynomialGF2n.
     *
     * @param s the scalar to multiply
     * @return <i>this</i> x <i>s</i>
     * @throws DifferentFieldsException if <tt>this</tt> and <tt>s</tt> are not defined over
     * the same field.
     */
    public final GF2nPolynomial scalarMultiply(GF2nElement s)
        throws RuntimeException
    {
        GF2nPolynomial result = new GF2nPolynomial(size());
        int i;
        for (i = 0; i < size(); i++)
        {
            result.coeff[i] = (GF2nElement)coeff[i].multiply(s); // result[i]
            // =
            // a[i]*s
        }
        return result;
    }

    /**
     * Multiplies <i>this</i> by <i>b</i> and returns the result in a new
     * PolynomialGF2n.
     *
     * @param b the PolynomialGF2n to multiply
     * @return <i>this</i> * <i>b</i>
     * @throws DifferentFieldsException if <tt>this</tt> and <tt>b</tt> are not defined over
     * the same field.
     */
    public final GF2nPolynomial multiply(GF2nPolynomial b)
        throws RuntimeException
    {
        int i, j;
        int aDegree = size();
        int bDegree = b.size();
        if (aDegree != bDegree)
        {
            throw new IllegalArgumentException(
                "PolynomialGF2n.multiply: this and b must "
                    + "have the same size!");
        }
        GF2nPolynomial result = new GF2nPolynomial((aDegree << 1) - 1);
        for (i = 0; i < size(); i++)
        {
            for (j = 0; j < b.size(); j++)
            {
                if (result.coeff[i + j] == null)
                {
                    result.coeff[i + j] = (GF2nElement)coeff[i]
                        .multiply(b.coeff[j]);
                }
                else
                {
                    result.coeff[i + j] = (GF2nElement)result.coeff[i + j]
                        .add(coeff[i].multiply(b.coeff[j]));
                }
            }
        }
        return result;
    }

    /**
     * Multiplies <i>this</i> by <i>b</i>, reduces the result by <i>g</i> and
     * returns it in a new PolynomialGF2n.
     *
     * @param b the PolynomialGF2n to multiply
     * @param g the modul
     * @return <i>this</i> * <i>b</i> mod <i>g</i>
     * @throws DifferentFieldsException if <tt>this</tt>, <tt>b</tt> and <tt>g</tt> are
     * not all defined over the same field.
     */
    public final GF2nPolynomial multiplyAndReduce(GF2nPolynomial b,
                                                  GF2nPolynomial g)
        throws RuntimeException,
        ArithmeticException
    {
        return multiply(b).reduce(g);
    }

    /**
     * Reduces <i>this</i> by <i>g</i> and returns the result in a new
     * PolynomialGF2n.
     *
     * @param g -
     *          the modulus
     * @return <i>this</i> % <i>g</i>
     * @throws DifferentFieldsException if <tt>this</tt> and <tt>g</tt> are not defined over
     * the same field.
     */
    public final GF2nPolynomial reduce(GF2nPolynomial g)
        throws RuntimeException, ArithmeticException
    {
        return remainder(g); // return this % g
    }

    /**
     * Shifts left <i>this</i> by <i>amount</i> and stores the result in
     * <i>this</i> PolynomialGF2n.
     *
     * @param amount the amount to shift the coefficients
     */
    public final void shiftThisLeft(int amount)
    {
        if (amount > 0)
        {
            int i;
            int oldSize = size;
            GF2nField f = coeff[0].getField();
            enlarge(size + amount);
            for (i = oldSize - 1; i >= 0; i--)
            {
                coeff[i + amount] = coeff[i];
            }
            if (coeff[0] instanceof GF2nPolynomialElement)
            {
                for (i = amount - 1; i >= 0; i--)
                {
                    coeff[i] = GF2nPolynomialElement
                        .ZERO((GF2nPolynomialField)f);
                }
            }
            else if (coeff[0] instanceof GF2nONBElement)
            {
                for (i = amount - 1; i >= 0; i--)
                {
                    coeff[i] = GF2nONBElement.ZERO((GF2nONBField)f);
                }
            }
        }
    }

    public final GF2nPolynomial shiftLeft(int amount)
    {
        if (amount <= 0)
        {
            return new GF2nPolynomial(this);
        }
        GF2nPolynomial result = new GF2nPolynomial(size + amount, coeff[0]);
        result.assignZeroToElements();
        for (int i = 0; i < size; i++)
        {
            result.coeff[i + amount] = coeff[i];
        }
        return result;
    }

    /**
     * Divides <i>this</i> by <i>b</i> and stores the result in a new
     * PolynomialGF2n[2], quotient in result[0] and remainder in result[1].
     *
     * @param b the divisor
     * @return the quotient and remainder of <i>this</i> / <i>b</i>
     * @throws DifferentFieldsException if <tt>this</tt> and <tt>b</tt> are not defined over
     * the same field.
     */
    public final GF2nPolynomial[] divide(GF2nPolynomial b)
        throws RuntimeException, ArithmeticException
    {
        GF2nPolynomial[] result = new GF2nPolynomial[2];
        GF2nPolynomial a = new GF2nPolynomial(this);
        a.shrink();
        GF2nPolynomial shift;
        GF2nElement factor;
        int bDegree = b.getDegree();
        GF2nElement inv = (GF2nElement)b.coeff[bDegree].invert();
        if (a.getDegree() < bDegree)
        {
            result[0] = new GF2nPolynomial(this);
            result[0].assignZeroToElements();
            result[0].shrink();
            result[1] = new GF2nPolynomial(this);
            result[1].shrink();
            return result;
        }
        result[0] = new GF2nPolynomial(this);
        result[0].assignZeroToElements();
        int i = a.getDegree() - bDegree;
        while (i >= 0)
        {
            factor = (GF2nElement)a.coeff[a.getDegree()].multiply(inv);
            shift = b.scalarMultiply(factor);
            shift.shiftThisLeft(i);
            a = a.add(shift);
            a.shrink();
            result[0].coeff[i] = (GF2nElement)factor.clone();
            i = a.getDegree() - bDegree;
        }
        result[1] = a;
        result[0].shrink();
        return result;
    }

    /**
     * Divides <i>this</i> by <i>b</i> and stores the remainder in a new
     * PolynomialGF2n.
     *
     * @param b the divisor
     * @return the remainder <i>this</i> % <i>b</i>
     * @throws DifferentFieldsException if <tt>this</tt> and <tt>b</tt> are not defined over
     * the same field.
     */
    public final GF2nPolynomial remainder(GF2nPolynomial b)
        throws RuntimeException, ArithmeticException
    {
        GF2nPolynomial[] result = new GF2nPolynomial[2];
        result = divide(b);
        return result[1];
    }

    /**
     * Divides <i>this</i> by <i>b</i> and stores the quotient in a new
     * PolynomialGF2n.
     *
     * @param b the divisor
     * @return the quotient <i>this</i> / <i>b</i>
     * @throws DifferentFieldsException if <tt>this</tt> and <tt>b</tt> are not defined over
     * the same field.
     */
    public final GF2nPolynomial quotient(GF2nPolynomial b)
        throws RuntimeException, ArithmeticException
    {
        GF2nPolynomial[] result = new GF2nPolynomial[2];
        result = divide(b);
        return result[0];
    }

    /**
     * Computes the greatest common divisor of <i>this</i> and <i>g</i> and
     * returns the result in a new PolynomialGF2n.
     *
     * @param g -
     *          a GF2nPolynomial
     * @return gcd(<i>this</i>, <i>g</i>)
     * @throws DifferentFieldsException if the coefficients of <i>this</i> and <i>g</i> use
     * different fields
     * @throws ArithmeticException if coefficients are zero.
     */
    public final GF2nPolynomial gcd(GF2nPolynomial g)
        throws RuntimeException, ArithmeticException
    {
        GF2nPolynomial a = new GF2nPolynomial(this);
        GF2nPolynomial b = new GF2nPolynomial(g);
        a.shrink();
        b.shrink();
        GF2nPolynomial c;
        GF2nPolynomial result;
        GF2nElement alpha;
        while (!b.isZero())
        {
            c = a.remainder(b);
            a = b;
            b = c;
        }
        alpha = a.coeff[a.getDegree()];
        result = a.scalarMultiply((GF2nElement)alpha.invert());
        return result;
    }

}
