package org.bouncycastle.math.ec.custom.sec;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.Nat;

public class SecP192K1Point extends ECPoint
{
    /**
     * Create a point which encodes with point compression.
     * 
     * @param curve
     *            the curve to use
     * @param x
     *            affine x co-ordinate
     * @param y
     *            affine y co-ordinate
     * 
     * @deprecated Use ECCurve.createPoint to construct points
     */
    public SecP192K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y)
    {
        this(curve, x, y, false);
    }

    /**
     * Create a point that encodes with or without point compresion.
     * 
     * @param curve
     *            the curve to use
     * @param x
     *            affine x co-ordinate
     * @param y
     *            affine y co-ordinate
     * @param withCompression
     *            if true encode with point compression
     * 
     * @deprecated per-point compression property will be removed, refer
     *             {@link #getEncoded(boolean)}
     */
    public SecP192K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        super(curve, x, y);

        if ((x == null) != (y == null))
        {
            throw new IllegalArgumentException("Exactly one of the field elements is null");
        }

        this.withCompression = withCompression;
    }

    SecP192K1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs,
        boolean withCompression)
    {
        super(curve, x, y, zs);

        this.withCompression = withCompression;
    }

    protected ECPoint detach()
    {
        return new SecP192K1Point(null, getAffineXCoord(), getAffineYCoord());
    }

    protected boolean getCompressionYTilde()
    {
        return this.getAffineYCoord().testBitZero();
    }

    // B.3 pg 62
    public ECPoint add(ECPoint b)
    {
        if (this.isInfinity())
        {
            return b;
        }
        if (b.isInfinity())
        {
            return this;
        }
        if (this == b)
        {
            return twice();
        }

        ECCurve curve = this.getCurve();

        SecP192K1FieldElement X1 = (SecP192K1FieldElement)this.x, Y1 = (SecP192K1FieldElement)this.y;
        SecP192K1FieldElement X2 = (SecP192K1FieldElement)b.getXCoord(), Y2 = (SecP192K1FieldElement)b.getYCoord();

        SecP192K1FieldElement Z1 = (SecP192K1FieldElement)this.zs[0];
        SecP192K1FieldElement Z2 = (SecP192K1FieldElement)b.getZCoord(0);

        int c;
        int[] tt1 = Nat192.createExt();
        int[] t2 = Nat192.create();
        int[] t3 = Nat192.create();
        int[] t4 = Nat192.create();

        boolean Z1IsOne = Z1.isOne();
        int[] U2, S2;
        if (Z1IsOne)
        {
            U2 = X2.x;
            S2 = Y2.x;
        }
        else
        {
            S2 = t3;
            SecP192K1Field.square(Z1.x, S2);

            U2 = t2;
            SecP192K1Field.multiply(S2, X2.x, U2);

            SecP192K1Field.multiply(S2, Z1.x, S2);
            SecP192K1Field.multiply(S2, Y2.x, S2);
        }

        boolean Z2IsOne = Z2.isOne();
        int[] U1, S1;
        if (Z2IsOne)
        {
            U1 = X1.x;
            S1 = Y1.x;
        }
        else
        {
            S1 = t4;
            SecP192K1Field.square(Z2.x, S1);

            U1 = tt1;
            SecP192K1Field.multiply(S1, X1.x, U1);

            SecP192K1Field.multiply(S1, Z2.x, S1);
            SecP192K1Field.multiply(S1, Y1.x, S1);
        }

        int[] H = Nat192.create();
        SecP192K1Field.subtract(U1, U2, H);

        int[] R = t2;
        SecP192K1Field.subtract(S1, S2, R);

        // Check if b == this or b == -this
        if (Nat192.isZero(H))
        {
            if (Nat192.isZero(R))
            {
                // this == b, i.e. this must be doubled
                return this.twice();
            }

            // this == -b, i.e. the result is the point at infinity
            return curve.getInfinity();
        }

        int[] HSquared = t3;
        SecP192K1Field.square(H, HSquared);

        int[] G = Nat192.create();
        SecP192K1Field.multiply(HSquared, H, G);

        int[] V = t3;
        SecP192K1Field.multiply(HSquared, U1, V);

        SecP192K1Field.negate(G, G);
        Nat192.mul(S1, G, tt1);

        c = Nat192.addBothTo(V, V, G);
        SecP192K1Field.reduce32(c, G);

        SecP192K1FieldElement X3 = new SecP192K1FieldElement(t4);
        SecP192K1Field.square(R, X3.x);
        SecP192K1Field.subtract(X3.x, G, X3.x);

        SecP192K1FieldElement Y3 = new SecP192K1FieldElement(G);
        SecP192K1Field.subtract(V, X3.x, Y3.x);
        SecP192K1Field.multiplyAddToExt(Y3.x, R, tt1);
        SecP192K1Field.reduce(tt1, Y3.x);

        SecP192K1FieldElement Z3 = new SecP192K1FieldElement(H);
        if (!Z1IsOne)
        {
            SecP192K1Field.multiply(Z3.x, Z1.x, Z3.x);
        }
        if (!Z2IsOne)
        {
            SecP192K1Field.multiply(Z3.x, Z2.x, Z3.x);
        }

        ECFieldElement[] zs = new ECFieldElement[] { Z3 };

        return new SecP192K1Point(curve, X3, Y3, zs, this.withCompression);
    }

    // B.3 pg 62
    public ECPoint twice()
    {
        if (this.isInfinity())
        {
            return this;
        }

        ECCurve curve = this.getCurve();

        SecP192K1FieldElement Y1 = (SecP192K1FieldElement)this.y;
        if (Y1.isZero())
        {
            return curve.getInfinity();
        }

        SecP192K1FieldElement X1 = (SecP192K1FieldElement)this.x, Z1 = (SecP192K1FieldElement)this.zs[0];

        int c;
        
        int[] Y1Squared = Nat192.create();
        SecP192K1Field.square(Y1.x, Y1Squared);

        int[] T = Nat192.create();
        SecP192K1Field.square(Y1Squared, T);

        int[] M = Nat192.create();
        SecP192K1Field.square(X1.x, M);
        c = Nat192.addBothTo(M, M, M);
        SecP192K1Field.reduce32(c, M);

        int[] S = Y1Squared;
        SecP192K1Field.multiply(Y1Squared, X1.x, S);
        c = Nat.shiftUpBits(6, S, 2, 0);
        SecP192K1Field.reduce32(c, S);

        int[] t1 = Nat192.create();
        c = Nat.shiftUpBits(6, T, 3, 0, t1);
        SecP192K1Field.reduce32(c, t1);

        SecP192K1FieldElement X3 = new SecP192K1FieldElement(T);
        SecP192K1Field.square(M, X3.x);
        SecP192K1Field.subtract(X3.x, S, X3.x);
        SecP192K1Field.subtract(X3.x, S, X3.x);

        SecP192K1FieldElement Y3 = new SecP192K1FieldElement(S);
        SecP192K1Field.subtract(S, X3.x, Y3.x);
        SecP192K1Field.multiply(Y3.x, M, Y3.x);
        SecP192K1Field.subtract(Y3.x, t1, Y3.x);

        SecP192K1FieldElement Z3 = new SecP192K1FieldElement(M);
        SecP192K1Field.twice(Y1.x, Z3.x);
        if (!Z1.isOne())
        {
            SecP192K1Field.multiply(Z3.x, Z1.x, Z3.x);
        }

        return new SecP192K1Point(curve, X3, Y3, new ECFieldElement[] { Z3 }, this.withCompression);
    }

    public ECPoint twicePlus(ECPoint b)
    {
        if (this == b)
        {
            return threeTimes();
        }
        if (this.isInfinity())
        {
            return b;
        }
        if (b.isInfinity())
        {
            return twice();
        }

        ECFieldElement Y1 = this.y;
        if (Y1.isZero())
        {
            return b;
        }

        return twice().add(b);
    }

    public ECPoint threeTimes()
    {
        if (this.isInfinity() || this.y.isZero())
        {
            return this;
        }

        // NOTE: Be careful about recursions between twicePlus and threeTimes
        return twice().add(this);
    }

    // D.3.2 pg 102 (see Note:)
    public ECPoint subtract(ECPoint b)
    {
        if (b.isInfinity())
        {
            return this;
        }

        // Add -b
        return add(b.negate());
    }

    public ECPoint negate()
    {
        if (this.isInfinity())
        {
            return this;
        }

        return new SecP192K1Point(curve, this.x, this.y.negate(), this.zs, this.withCompression);
    }
}
