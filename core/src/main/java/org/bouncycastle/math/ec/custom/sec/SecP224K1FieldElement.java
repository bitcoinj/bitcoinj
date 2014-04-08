package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.Mod;
import org.bouncycastle.util.Arrays;

public class SecP224K1FieldElement extends ECFieldElement
{
    public static final BigInteger Q = SecP224K1Curve.q;

    // Calculated as ECConstants.TWO.modPow(Q.shiftRight(2), Q)
    private static final int[] PRECOMP_POW2 = new int[]{ 0x33bfd202, 0xdcfad133, 0x2287624a, 0xc3811ba8,
        0xa85558fc, 0x1eaef5d7, 0x8edf154c };

    protected int[] x;

    public SecP224K1FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid for SecP224K1FieldElement");
        }

        this.x = SecP224K1Field.fromBigInteger(x);
    }

    public SecP224K1FieldElement()
    {
        this.x = Nat224.create();
    }

    protected SecP224K1FieldElement(int[] x)
    {
        this.x = x;
    }

    public boolean isZero()
    {
        return Nat224.isZero(x);
    }

    public boolean isOne()
    {
        return Nat224.isOne(x);
    }

    public boolean testBitZero()
    {
        return Nat224.getBit(x, 0) == 1;
    }

    public BigInteger toBigInteger()
    {
        return Nat224.toBigInteger(x);
    }

    public String getFieldName()
    {
        return "SecP224K1Field";
    }

    public int getFieldSize()
    {
        return Q.bitLength();
    }

    public ECFieldElement add(ECFieldElement b)
    {
        int[] z = Nat224.create();
        SecP224K1Field.add(x, ((SecP224K1FieldElement)b).x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        int[] z = Nat224.create();
        SecP224K1Field.addOne(x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        int[] z = Nat224.create();
        SecP224K1Field.subtract(x, ((SecP224K1FieldElement)b).x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        int[] z = Nat224.create();
        SecP224K1Field.multiply(x, ((SecP224K1FieldElement)b).x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement divide(ECFieldElement b)
    {
//        return multiply(b.invert());
        int[] z = Nat224.create();
        Mod.invert(SecP224K1Field.P, ((SecP224K1FieldElement)b).x, z);
        SecP224K1Field.multiply(z, x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement negate()
    {
        int[] z = Nat224.create();
        SecP224K1Field.negate(x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement square()
    {
        int[] z = Nat224.create();
        SecP224K1Field.square(x, z);
        return new SecP224K1FieldElement(z);
    }

    public ECFieldElement invert()
    {
//        return new SecP224K1FieldElement(toBigInteger().modInverse(Q));
        int[] z = Nat224.create();
        Mod.invert(SecP224K1Field.P, x, z);
        return new SecP224K1FieldElement(z);
    }

    // D.1.4 91
    /**
     * return a sqrt root - the routine verifies that the calculation returns the right value - if
     * none exists it returns null.
     */
    public ECFieldElement sqrt()
    {
        /*
         * Q == 8m + 5, so we use Pocklington's method for this case.
         *
         * First, raise this element to the exponent 2^221 - 2^29 - 2^9 - 2^8 - 2^6 - 2^4 - 2^1 (i.e. m + 1)
         * 
         * Breaking up the exponent's binary representation into "repunits", we get:
         * { 191 1s } { 1 0s } { 19 1s } { 2 0s } { 1 1s } { 1 0s} { 1 1s } { 1 0s} { 3 1s } { 1 0s}
         * 
         * Therefore we need an addition chain containing 1, 3, 19, 191 (the lengths of the repunits)
         * We use: [1], 2, [3], 4, 8, 11, [19], 23, 42, 84, 107, [191]
         */

        int[] x1 = this.x;
        if (Nat224.isZero(x1) || Nat224.isOne(x1))
        {
            return this;
        }

        int[] x2 = Nat224.create();
        SecP224K1Field.square(x1, x2);
        SecP224K1Field.multiply(x2, x1, x2);
        int[] x3 = x2;
        SecP224K1Field.square(x2, x3);
        SecP224K1Field.multiply(x3, x1, x3);
        int[] x4 = Nat224.create();
        SecP224K1Field.square(x3, x4);
        SecP224K1Field.multiply(x4, x1, x4);
        int[] x8 = Nat224.create();
        SecP224K1Field.squareN(x4, 4, x8);
        SecP224K1Field.multiply(x8, x4, x8);
        int[] x11 = Nat224.create();
        SecP224K1Field.squareN(x8, 3, x11);
        SecP224K1Field.multiply(x11, x3, x11);
        int[] x19 = x11;
        SecP224K1Field.squareN(x11, 8, x19);
        SecP224K1Field.multiply(x19, x8, x19);
        int[] x23 = x8;
        SecP224K1Field.squareN(x19, 4, x23);
        SecP224K1Field.multiply(x23, x4, x23);
        int[] x42 = x4;
        SecP224K1Field.squareN(x23, 19, x42);
        SecP224K1Field.multiply(x42, x19, x42);
        int[] x84 = Nat224.create();
        SecP224K1Field.squareN(x42, 42, x84);
        SecP224K1Field.multiply(x84, x42, x84);
        int[] x107 = x42;
        SecP224K1Field.squareN(x84, 23, x107);
        SecP224K1Field.multiply(x107, x23, x107);
        int[] x191 = x23;
        SecP224K1Field.squareN(x107, 84, x191);
        SecP224K1Field.multiply(x191, x84, x191);

        int[] t1 = x191;
        SecP224K1Field.squareN(t1, 20, t1);
        SecP224K1Field.multiply(t1, x19, t1);
        SecP224K1Field.squareN(t1, 3, t1);
        SecP224K1Field.multiply(t1, x1, t1);
        SecP224K1Field.squareN(t1, 2, t1);
        SecP224K1Field.multiply(t1, x1, t1);
        SecP224K1Field.squareN(t1, 4, t1);
        SecP224K1Field.multiply(t1, x3, t1);
        SecP224K1Field.square(t1, t1);

        int[] t2 = x84;
        SecP224K1Field.square(t1, t2);

        if (Nat224.eq(x1, t2))
        {
            return new SecP224K1FieldElement(t1);
        }

        /*
         * If the first guess is incorrect, we multiply by a precomputed power of 2 to get the second guess,
         * which is ((4x)^(m + 1))/2 mod Q
         */
        SecP224K1Field.multiply(t1, PRECOMP_POW2, t1);

        SecP224K1Field.square(t1, t2);

        if (Nat224.eq(x1, t2))
        {
            return new SecP224K1FieldElement(t1);
        }

        return null;
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecP224K1FieldElement))
        {
            return false;
        }

        SecP224K1FieldElement o = (SecP224K1FieldElement)other;
        return Nat224.eq(x, o.x);
    }

    public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x, 0, 7);
    }
}
