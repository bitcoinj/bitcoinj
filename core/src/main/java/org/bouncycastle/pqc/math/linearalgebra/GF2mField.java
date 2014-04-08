package org.bouncycastle.pqc.math.linearalgebra;

import java.security.SecureRandom;

/**
 * This class describes operations with elements from the finite field F =
 * GF(2^m). ( GF(2^m)= GF(2)[A] where A is a root of irreducible polynomial with
 * degree m, each field element B has a polynomial basis representation, i.e. it
 * is represented by a different binary polynomial of degree less than m, B =
 * poly(A) ) All operations are defined only for field with 1&lt; m &lt;32. For the
 * representation of field elements the map f: F-&gt;Z, poly(A)-&gt;poly(2) is used,
 * where integers have the binary representation. For example: A^7+A^3+A+1 -&gt;
 * (00...0010001011)=139 Also for elements type Integer is used.
 *
 * @see PolynomialRingGF2
 */
public class GF2mField
{

    /*
      * degree - degree of the field polynomial - the field polynomial ring -
      * polynomial ring over the finite field GF(2)
      */

    private int degree = 0;

    private int polynomial;

    /**
     * create a finite field GF(2^m)
     *
     * @param degree the degree of the field
     */
    public GF2mField(int degree)
    {
        if (degree >= 32)
        {
            throw new IllegalArgumentException(
                " Error: the degree of field is too large ");
        }
        if (degree < 1)
        {
            throw new IllegalArgumentException(
                " Error: the degree of field is non-positive ");
        }
        this.degree = degree;
        polynomial = PolynomialRingGF2.getIrreduciblePolynomial(degree);
    }

    /**
     * create a finite field GF(2^m) with the fixed field polynomial
     *
     * @param degree the degree of the field
     * @param poly   the field polynomial
     */
    public GF2mField(int degree, int poly)
    {
        if (degree != PolynomialRingGF2.degree(poly))
        {
            throw new IllegalArgumentException(
                " Error: the degree is not correct");
        }
        if (!PolynomialRingGF2.isIrreducible(poly))
        {
            throw new IllegalArgumentException(
                " Error: given polynomial is reducible");
        }
        this.degree = degree;
        polynomial = poly;

    }

    public GF2mField(byte[] enc)
    {
        if (enc.length != 4)
        {
            throw new IllegalArgumentException(
                "byte array is not an encoded finite field");
        }
        polynomial = LittleEndianConversions.OS2IP(enc);
        if (!PolynomialRingGF2.isIrreducible(polynomial))
        {
            throw new IllegalArgumentException(
                "byte array is not an encoded finite field");
        }

        degree = PolynomialRingGF2.degree(polynomial);
    }

    public GF2mField(GF2mField field)
    {
        degree = field.degree;
        polynomial = field.polynomial;
    }

    /**
     * return degree of the field
     *
     * @return degree of the field
     */
    public int getDegree()
    {
        return degree;
    }

    /**
     * return the field polynomial
     *
     * @return the field polynomial
     */
    public int getPolynomial()
    {
        return polynomial;
    }

    /**
     * return the encoded form of this field
     *
     * @return the field in byte array form
     */
    public byte[] getEncoded()
    {
        return LittleEndianConversions.I2OSP(polynomial);
    }

    /**
     * Return sum of two elements
     *
     * @param a
     * @param b
     * @return a+b
     */
    public int add(int a, int b)
    {
        return a ^ b;
    }

    /**
     * Return product of two elements
     *
     * @param a
     * @param b
     * @return a*b
     */
    public int mult(int a, int b)
    {
        return PolynomialRingGF2.modMultiply(a, b, polynomial);
    }

    /**
     * compute exponentiation a^k
     *
     * @param a a field element a
     * @param k k degree
     * @return a^k
     */
    public int exp(int a, int k)
    {
        if (a == 0)
        {
            return 0;
        }
        if (a == 1)
        {
            return 1;
        }
        int result = 1;
        if (k < 0)
        {
            a = inverse(a);
            k = -k;
        }
        while (k != 0)
        {
            if ((k & 1) == 1)
            {
                result = mult(result, a);
            }
            a = mult(a, a);
            k >>>= 1;
        }
        return result;
    }

    /**
     * compute the multiplicative inverse of a
     *
     * @param a a field element a
     * @return a<sup>-1</sup>
     */
    public int inverse(int a)
    {
        int d = (1 << degree) - 2;

        return exp(a, d);
    }

    /**
     * compute the square root of an integer
     *
     * @param a a field element a
     * @return a<sup>1/2</sup>
     */
    public int sqRoot(int a)
    {
        for (int i = 1; i < degree; i++)
        {
            a = mult(a, a);
        }
        return a;
    }

    /**
     * create a random field element using PRNG sr
     *
     * @param sr SecureRandom
     * @return a random element
     */
    public int getRandomElement(SecureRandom sr)
    {
        int result = RandUtils.nextInt(sr, 1 << degree);
        return result;
    }

    /**
     * create a random non-zero field element
     *
     * @return a random element
     */
    public int getRandomNonZeroElement()
    {
        return getRandomNonZeroElement(new SecureRandom());
    }

    /**
     * create a random non-zero field element using PRNG sr
     *
     * @param sr SecureRandom
     * @return a random non-zero element
     */
    public int getRandomNonZeroElement(SecureRandom sr)
    {
        int controltime = 1 << 20;
        int count = 0;
        int result = RandUtils.nextInt(sr, 1 << degree);
        while ((result == 0) && (count < controltime))
        {
            result = RandUtils.nextInt(sr, 1 << degree);
            count++;
        }
        if (count == controltime)
        {
            result = 1;
        }
        return result;
    }

    /**
     * @return true if e is encoded element of this field and false otherwise
     */
    public boolean isElementOfThisField(int e)
    {
        // e is encoded element of this field iff 0<= e < |2^m|
        if (degree == 31)
        {
            return e >= 0;
        }
        return e >= 0 && e < (1 << degree);
    }

    /*
      * help method for visual control
      */
    public String elementToStr(int a)
    {
        String s = "";
        for (int i = 0; i < degree; i++)
        {
            if (((byte)a & 0x01) == 0)
            {
                s = "0" + s;
            }
            else
            {
                s = "1" + s;
            }
            a >>>= 1;
        }
        return s;
    }

    /**
     * checks if given object is equal to this field.
     * <p>
     * The method returns false whenever the given object is not GF2m.
     *
     * @param other object
     * @return true or false
     */
    public boolean equals(Object other)
    {
        if ((other == null) || !(other instanceof GF2mField))
        {
            return false;
        }

        GF2mField otherField = (GF2mField)other;

        if ((degree == otherField.degree)
            && (polynomial == otherField.polynomial))
        {
            return true;
        }

        return false;
    }

    public int hashCode()
    {
        return polynomial;
    }

    /**
     * Returns a human readable form of this field.
     *
     * @return a human readable form of this field.
     */
    public String toString()
    {
        String str = "Finite Field GF(2^" + degree + ") = " + "GF(2)[X]/<"
            + polyToString(polynomial) + "> ";
        return str;
    }

    private static String polyToString(int p)
    {
        String str = "";
        if (p == 0)
        {
            str = "0";
        }
        else
        {
            byte b = (byte)(p & 0x01);
            if (b == 1)
            {
                str = "1";
            }
            p >>>= 1;
            int i = 1;
            while (p != 0)
            {
                b = (byte)(p & 0x01);
                if (b == 1)
                {
                    str = str + "+x^" + i;
                }
                p >>>= 1;
                i++;
            }
        }
        return str;
    }

}
