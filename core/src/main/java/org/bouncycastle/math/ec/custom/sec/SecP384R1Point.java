package org.bouncycastle.math.ec.custom.sec;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.Nat;

public class SecP384R1Point extends ECPoint
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
    public SecP384R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y)
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
    public SecP384R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        super(curve, x, y);

        if ((x == null) != (y == null))
        {
            throw new IllegalArgumentException("Exactly one of the field elements is null");
        }

        this.withCompression = withCompression;
    }

    SecP384R1Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        super(curve, x, y, zs);

        this.withCompression = withCompression;
    }

    protected ECPoint detach()
    {
        return new SecP384R1Point(null, getAffineXCoord(), getAffineYCoord());
    }

    protected boolean getCompressionYTilde()
    {
        return this.getAffineYCoord().testBitZero();
    }

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

        SecP384R1FieldElement X1 = (SecP384R1FieldElement)this.x, Y1 = (SecP384R1FieldElement)this.y;
        SecP384R1FieldElement X2 = (SecP384R1FieldElement)b.getXCoord(), Y2 = (SecP384R1FieldElement)b.getYCoord();

        SecP384R1FieldElement Z1 = (SecP384R1FieldElement)this.zs[0];
        SecP384R1FieldElement Z2 = (SecP384R1FieldElement)b.getZCoord(0);

        int c;
        int[] tt1 = Nat.create(24);
        int[] tt2 = Nat.create(24);
        int[] t3 = Nat.create(12);
        int[] t4 = Nat.create(12);

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
            SecP384R1Field.square(Z1.x, S2);

            U2 = tt2;
            SecP384R1Field.multiply(S2, X2.x, U2);

            SecP384R1Field.multiply(S2, Z1.x, S2);
            SecP384R1Field.multiply(S2, Y2.x, S2);
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
            SecP384R1Field.square(Z2.x, S1);

            U1 = tt1;
            SecP384R1Field.multiply(S1, X1.x, U1);

            SecP384R1Field.multiply(S1, Z2.x, S1);
            SecP384R1Field.multiply(S1, Y1.x, S1);
        }

        int[] H = Nat.create(12);
        SecP384R1Field.subtract(U1, U2, H);

        int[] R = Nat.create(12);
        SecP384R1Field.subtract(S1, S2, R);

        // Check if b == this or b == -this
        if (Nat.isZero(12, H))
        {
            if (Nat.isZero(12, R))
            {
                // this == b, i.e. this must be doubled
                return this.twice();
            }

            // this == -b, i.e. the result is the point at infinity
            return curve.getInfinity();
        }

        int[] HSquared = t3;
        SecP384R1Field.square(H, HSquared);

        int[] G = Nat.create(12);
        SecP384R1Field.multiply(HSquared, H, G);

        int[] V = t3;
        SecP384R1Field.multiply(HSquared, U1, V);

        SecP384R1Field.negate(G, G);
        Nat384.mul(S1, G, tt1);

        c = Nat.addBothTo(12, V, V, G);
        SecP384R1Field.reduce32(c, G);

        SecP384R1FieldElement X3 = new SecP384R1FieldElement(t4);
        SecP384R1Field.square(R, X3.x);
        SecP384R1Field.subtract(X3.x, G, X3.x);

        SecP384R1FieldElement Y3 = new SecP384R1FieldElement(G);
        SecP384R1Field.subtract(V, X3.x, Y3.x);
        Nat384.mul(Y3.x, R, tt2);
        SecP384R1Field.addExt(tt1, tt2, tt1);
        SecP384R1Field.reduce(tt1, Y3.x);

        SecP384R1FieldElement Z3 = new SecP384R1FieldElement(H);
        if (!Z1IsOne)
        {
            SecP384R1Field.multiply(Z3.x, Z1.x, Z3.x);
        }
        if (!Z2IsOne)
        {
            SecP384R1Field.multiply(Z3.x, Z2.x, Z3.x);
        }

        ECFieldElement[] zs = new ECFieldElement[]{ Z3 };

        return new SecP384R1Point(curve, X3, Y3, zs, this.withCompression);
    }

    public ECPoint twice()
    {
        if (this.isInfinity())
        {
            return this;
        }

        ECCurve curve = this.getCurve();

        SecP384R1FieldElement Y1 = (SecP384R1FieldElement)this.y;
        if (Y1.isZero())
        {
            return curve.getInfinity();
        }

        SecP384R1FieldElement X1 = (SecP384R1FieldElement)this.x, Z1 = (SecP384R1FieldElement)this.zs[0];

        int c;
        int[] t1 = Nat.create(12);
        int[] t2 = Nat.create(12);

        int[] Y1Squared = Nat.create(12);
        SecP384R1Field.square(Y1.x, Y1Squared);

        int[] T = Nat.create(12);
        SecP384R1Field.square(Y1Squared, T);

        boolean Z1IsOne = Z1.isOne();

        int[] Z1Squared = Z1.x;
        if (!Z1IsOne)
        {
            Z1Squared = t2;
            SecP384R1Field.square(Z1.x, Z1Squared);
        }

        SecP384R1Field.subtract(X1.x, Z1Squared, t1);

        int[] M = t2;
        SecP384R1Field.add(X1.x, Z1Squared, M);
        SecP384R1Field.multiply(M, t1, M);
        c = Nat.addBothTo(12, M, M, M);
        SecP384R1Field.reduce32(c, M);

        int[] S = Y1Squared;
        SecP384R1Field.multiply(Y1Squared, X1.x, S);
        c = Nat.shiftUpBits(12, S, 2, 0);
        SecP384R1Field.reduce32(c, S);

        c = Nat.shiftUpBits(12, T, 3, 0, t1);
        SecP384R1Field.reduce32(c, t1);

        SecP384R1FieldElement X3 = new SecP384R1FieldElement(T);
        SecP384R1Field.square(M, X3.x);
        SecP384R1Field.subtract(X3.x, S, X3.x);
        SecP384R1Field.subtract(X3.x, S, X3.x);

        SecP384R1FieldElement Y3 = new SecP384R1FieldElement(S);
        SecP384R1Field.subtract(S, X3.x, Y3.x);
        SecP384R1Field.multiply(Y3.x, M, Y3.x);
        SecP384R1Field.subtract(Y3.x, t1, Y3.x);

        SecP384R1FieldElement Z3 = new SecP384R1FieldElement(M);
        SecP384R1Field.twice(Y1.x, Z3.x);
        if (!Z1IsOne)
        {
            SecP384R1Field.multiply(Z3.x, Z1.x, Z3.x);
        }

        return new SecP384R1Point(curve, X3, Y3, new ECFieldElement[]{ Z3 }, this.withCompression);
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

        return new SecP384R1Point(curve, this.x, this.y.negate(), this.zs, this.withCompression);
    }
}
