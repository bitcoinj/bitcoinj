package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.Mod;
import org.bouncycastle.math.ec.Nat;
import org.bouncycastle.util.Arrays;

public class SecP521R1FieldElement extends ECFieldElement
{
    public static final BigInteger Q = SecP521R1Curve.q;

    protected int[] x;

    public SecP521R1FieldElement(BigInteger x)
    {
        if (x == null || x.signum() < 0 || x.compareTo(Q) >= 0)
        {
            throw new IllegalArgumentException("x value invalid for SecP521R1FieldElement");
        }

        this.x = SecP521R1Field.fromBigInteger(x);
    }

    public SecP521R1FieldElement()
    {
        this.x = Nat.create(17);
    }

    protected SecP521R1FieldElement(int[] x)
    {
        this.x = x;
    }

    public boolean isZero()
    {
        return Nat.isZero(17, x);
    }

    public boolean isOne()
    {
        return Nat.isOne(17, x);
    }

    public boolean testBitZero()
    {
        return Nat.getBit(x, 0) == 1;
    }

    public BigInteger toBigInteger()
    {
        return Nat.toBigInteger(17, x);
    }

    public String getFieldName()
    {
        return "SecP521R1Field";
    }

    public int getFieldSize()
    {
        return Q.bitLength();
    }

    public ECFieldElement add(ECFieldElement b)
    {
        int[] z = Nat.create(17);
        SecP521R1Field.add(x, ((SecP521R1FieldElement)b).x, z);
        return new SecP521R1FieldElement(z);
    }

    public ECFieldElement addOne()
    {
        int[] z = Nat.create(17);
        SecP521R1Field.addOne(x, z);
        return new SecP521R1FieldElement(z);
    }

    public ECFieldElement subtract(ECFieldElement b)
    {
        int[] z = Nat.create(17);
        SecP521R1Field.subtract(x, ((SecP521R1FieldElement)b).x, z);
        return new SecP521R1FieldElement(z);
    }

    public ECFieldElement multiply(ECFieldElement b)
    {
        int[] z = Nat.create(17);
        SecP521R1Field.multiply(x, ((SecP521R1FieldElement)b).x, z);
        return new SecP521R1FieldElement(z);
    }

    public ECFieldElement divide(ECFieldElement b)
    {
//        return multiply(b.invert());
        int[] z = Nat.create(17);
        Mod.invert(SecP521R1Field.P, ((SecP521R1FieldElement)b).x, z);
        SecP521R1Field.multiply(z, x, z);
        return new SecP521R1FieldElement(z);
    }

    public ECFieldElement negate()
    {
        int[] z = Nat.create(17);
        SecP521R1Field.negate(x, z);
        return new SecP521R1FieldElement(z);
    }

    public ECFieldElement square()
    {
        int[] z = Nat.create(17);
        SecP521R1Field.square(x, z);
        return new SecP521R1FieldElement(z);
    }

    public ECFieldElement invert()
    {
//        return new SecP521R1FieldElement(toBigInteger().modInverse(Q));
        int[] z = Nat.create(17);
        Mod.invert(SecP521R1Field.P, x, z);
        return new SecP521R1FieldElement(z);
    }

    // D.1.4 91
    /**
     * return a sqrt root - the routine verifies that the calculation returns the right value - if
     * none exists it returns null.
     */
    public ECFieldElement sqrt()
    {
        // Raise this element to the exponent 2^519

        int[] x1 = this.x;
        if (Nat.isZero(17, x1) || Nat.isOne(17, x1))
        {
            return this;
        }

        int[] t1 = Nat.create(17);
        int[] t2 = Nat.create(17);

        SecP521R1Field.squareN(x1, 519, t1);
        SecP521R1Field.square(t1, t2);

        return Nat.eq(17, x1, t2) ? new SecP521R1FieldElement(t1) : null;
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof SecP521R1FieldElement))
        {
            return false;
        }

        SecP521R1FieldElement o = (SecP521R1FieldElement)other;
        return Nat.eq(17, x, o.x);
    }

    public int hashCode()
    {
        return Q.hashCode() ^ Arrays.hashCode(x, 0, 17);
    }
}
