package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.Mod;
import org.bouncycastle.util.Arrays;

public class SecP192R1FieldElement extends ECFieldElement
{
    public static final BigInteger Q = SecP192R1Curve.q;

    protected int[] x;

    public SecP192R1FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid for SecP192R1FieldElement");
        }

        this.x = SecP192R1Field.fromBigInteger(x);
    }

    public SecP192R1FieldElement()
    {
        this.x = Nat192.create();
    }

    protected SecP192R1FieldElement(int[] x)
    {
        this.x = x;
    }

    public boolean isZero()
    {
        return Nat192.isZero(x);
    }

    public boolean isOne()
    {
        return Nat192.isOne(x);
    }

    public boolean testBitZero()
    {
        return Nat192.getBit(x, 0) == 1;
    }

    public BigInteger toBigInteger()
    {
        return Nat192.toBigInteger(x);
    }

    public String getFieldName()
    {
        return "SecP192R1Field";
    }

    public int getFieldSize()
    {
        return Q.bitLength();
    }

    public ECFieldElement add(ECFieldElement b)
    {
        int[] z = Nat192.create();
        SecP192R1Field.add(x, ((SecP192R1FieldElement)b).x, z);
        return new SecP192R1FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        int[] z = Nat192.create();
        SecP192R1Field.addOne(x, z);
        return new SecP192R1FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        int[] z = Nat192.create();
        SecP192R1Field.subtract(x, ((SecP192R1FieldElement)b).x, z);
        return new SecP192R1FieldElement(z);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        int[] z = Nat192.create();
        SecP192R1Field.multiply(x, ((SecP192R1FieldElement)b).x, z);
        return new SecP192R1FieldElement(z);
    }

    public ECFieldElement divide(ECFieldElement b)
    {
//        return multiply(b.invert());
        int[] z = Nat192.create();
        Mod.invert(SecP192R1Field.P, ((SecP192R1FieldElement)b).x, z);
        SecP192R1Field.multiply(z, x, z);
        return new SecP192R1FieldElement(z);
    }

    public ECFieldElement negate()
    {
        int[] z = Nat192.create();
        SecP192R1Field.negate(x, z);
        return new SecP192R1FieldElement(z);
    }

    public ECFieldElement square()
    {
        int[] z = Nat192.create();
        SecP192R1Field.square(x, z);
        return new SecP192R1FieldElement(z);
    }

    public ECFieldElement invert()
    {
//        return new SecP192R1FieldElement(toBigInteger().modInverse(Q));
        int[] z = Nat192.create();
        Mod.invert(SecP192R1Field.P, x, z);
        return new SecP192R1FieldElement(z);
    }

    // D.1.4 91
    /**
     * return a sqrt root - the routine verifies that the calculation returns the right value - if
     * none exists it returns null.
     */
    public ECFieldElement sqrt()
    {
        // Raise this element to the exponent 2^190 - 2^62

        int[] x1 = this.x;
        if (Nat192.isZero(x1) || Nat192.isOne(x1))
        {
            return this;
        }

        int[] t1 = Nat192.create();
        int[] t2 = Nat192.create();

        SecP192R1Field.square(x1, t1);
        SecP192R1Field.multiply(t1, x1, t1);

        SecP192R1Field.squareN(t1, 2, t2);
        SecP192R1Field.multiply(t2, t1, t2);

        SecP192R1Field.squareN(t2, 4, t1);
        SecP192R1Field.multiply(t1, t2, t1);

        SecP192R1Field.squareN(t1, 8, t2);
        SecP192R1Field.multiply(t2, t1, t2);

        SecP192R1Field.squareN(t2, 16, t1);
        SecP192R1Field.multiply(t1, t2, t1);

        SecP192R1Field.squareN(t1, 32, t2);
        SecP192R1Field.multiply(t2, t1, t2);

        SecP192R1Field.squareN(t2, 64, t1);
        SecP192R1Field.multiply(t1, t2, t1);

        SecP192R1Field.squareN(t1, 62, t1);
        SecP192R1Field.square(t1, t2);

        return Nat192.eq(x1, t2) ? new SecP192R1FieldElement(t1) : null;
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecP192R1FieldElement))
        {
            return false;
        }

        SecP192R1FieldElement o = (SecP192R1FieldElement)other;
        return Nat192.eq(x, o.x);
    }

    public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x, 0, 6);
    }
}
