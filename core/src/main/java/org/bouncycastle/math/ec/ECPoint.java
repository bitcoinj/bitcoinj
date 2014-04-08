package org.bouncycastle.math.ec;

import java.math.BigInteger;
import java.util.Hashtable;

/**
 * base class for points on elliptic curves.
 */
public abstract class ECPoint
{
    protected static ECFieldElement[] EMPTY_ZS = new ECFieldElement[0];

    protected static ECFieldElement[] getInitialZCoords(ECCurve curve)
    {
        // Cope with null curve, most commonly used by implicitlyCa
        int coord = null == curve ? ECCurve.COORD_AFFINE : curve.getCoordinateSystem();

        switch (coord)
        {
        case ECCurve.COORD_AFFINE:
        case ECCurve.COORD_LAMBDA_AFFINE:
            return EMPTY_ZS;
        default:
            break;
        }

        ECFieldElement one = curve.fromBigInteger(ECConstants.ONE);

        switch (coord)
        {
        case ECCurve.COORD_HOMOGENEOUS:
        case ECCurve.COORD_JACOBIAN:
        case ECCurve.COORD_LAMBDA_PROJECTIVE:
            return new ECFieldElement[]{ one };
        case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
            return new ECFieldElement[]{ one, one, one };
        case ECCurve.COORD_JACOBIAN_MODIFIED:
            return new ECFieldElement[]{ one, curve.getA() };
        default:
            throw new IllegalArgumentException("unknown coordinate system");
        }
    }

    protected ECCurve curve;
    protected ECFieldElement x;
    protected ECFieldElement y;
    protected ECFieldElement[] zs;

    protected boolean withCompression;

    // Hashtable is (String -> PreCompInfo)
    protected Hashtable preCompTable = null;

    protected ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y)
    {
        this(curve, x, y, getInitialZCoords(curve));
    }

    protected ECPoint(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)
    {
        this.curve = curve;
        this.x = x;
        this.y = y;
        this.zs = zs;
    }

    public final ECPoint getDetachedPoint()
    {
        return normalize().detach();
    }

    public ECCurve getCurve()
    {
        return curve;
    }

    protected abstract ECPoint detach();

    protected int getCurveCoordinateSystem()
    {
        // Cope with null curve, most commonly used by implicitlyCa
        return null == curve ? ECCurve.COORD_AFFINE : curve.getCoordinateSystem();
    }

    /**
     * Normalizes this point, and then returns the affine x-coordinate.
     * 
     * Note: normalization can be expensive, this method is deprecated in favour
     * of caller-controlled normalization.
     * 
     * @deprecated Use getAffineXCoord(), or normalize() and getXCoord(), instead
     */
    public ECFieldElement getX()
    {
        return normalize().getXCoord();
    }


    /**
     * Normalizes this point, and then returns the affine y-coordinate.
     * 
     * Note: normalization can be expensive, this method is deprecated in favour
     * of caller-controlled normalization.
     * 
     * @deprecated Use getAffineYCoord(), or normalize() and getYCoord(), instead
     */
    public ECFieldElement getY()
    {
        return normalize().getYCoord();
    }

    /**
     * Returns the affine x-coordinate after checking that this point is normalized.
     * 
     * @return The affine x-coordinate of this point
     * @throws IllegalStateException if the point is not normalized
     */
    public ECFieldElement getAffineXCoord()
    {
        checkNormalized();
        return getXCoord();
    }

    /**
     * Returns the affine y-coordinate after checking that this point is normalized
     * 
     * @return The affine y-coordinate of this point
     * @throws IllegalStateException if the point is not normalized
     */
    public ECFieldElement getAffineYCoord()
    {
        checkNormalized();
        return getYCoord();
    }

    /**
     * Returns the x-coordinate.
     * 
     * Caution: depending on the curve's coordinate system, this may not be the same value as in an
     * affine coordinate system; use normalize() to get a point where the coordinates have their
     * affine values, or use getAffineXCoord() if you expect the point to already have been
     * normalized.
     * 
     * @return the x-coordinate of this point
     */
    public ECFieldElement getXCoord()
    {
        return x;
    }

    /**
     * Returns the y-coordinate.
     * 
     * Caution: depending on the curve's coordinate system, this may not be the same value as in an
     * affine coordinate system; use normalize() to get a point where the coordinates have their
     * affine values, or use getAffineYCoord() if you expect the point to already have been
     * normalized.
     * 
     * @return the y-coordinate of this point
     */
    public ECFieldElement getYCoord()
    {
        return y;
    }

    public ECFieldElement getZCoord(int index)
    {
        return (index < 0 || index >= zs.length) ? null : zs[index];
    }

    public ECFieldElement[] getZCoords()
    {
        int zsLen = zs.length;
        if (zsLen == 0)
        {
            return zs;
        }
        ECFieldElement[] copy = new ECFieldElement[zsLen];
        System.arraycopy(zs, 0, copy, 0, zsLen);
        return copy;
    }

    protected final ECFieldElement getRawXCoord()
    {
        return x;
    }

    protected final ECFieldElement getRawYCoord()
    {
        return y;
    }

    protected final ECFieldElement[] getRawZCoords()
    {
        return zs;
    }

    protected void checkNormalized()
    {
        if (!isNormalized())
        {
            throw new IllegalStateException("point not in normal form");
        }
    }

    public boolean isNormalized()
    {
        int coord = this.getCurveCoordinateSystem();

        return coord == ECCurve.COORD_AFFINE
            || coord == ECCurve.COORD_LAMBDA_AFFINE
            || isInfinity()
            || zs[0].isOne();
    }

    /**
     * Normalization ensures that any projective coordinate is 1, and therefore that the x, y
     * coordinates reflect those of the equivalent point in an affine coordinate system.
     * 
     * @return a new ECPoint instance representing the same point, but with normalized coordinates
     */
    public ECPoint normalize()
    {
        if (this.isInfinity())
        {
            return this;
        }

        switch (this.getCurveCoordinateSystem())
        {
        case ECCurve.COORD_AFFINE:
        case ECCurve.COORD_LAMBDA_AFFINE:
        {
            return this;
        }
        default:
        {
            ECFieldElement Z1 = getZCoord(0);
            if (Z1.isOne())
            {
                return this;
            }

            return normalize(Z1.invert());
        }
        }
    }

    ECPoint normalize(ECFieldElement zInv)
    {
        switch (this.getCurveCoordinateSystem())
        {
        case ECCurve.COORD_HOMOGENEOUS:
        case ECCurve.COORD_LAMBDA_PROJECTIVE:
        {
            return createScaledPoint(zInv, zInv);
        }
        case ECCurve.COORD_JACOBIAN:
        case ECCurve.COORD_JACOBIAN_CHUDNOVSKY:
        case ECCurve.COORD_JACOBIAN_MODIFIED:
        {
            ECFieldElement zInv2 = zInv.square(), zInv3 = zInv2.multiply(zInv);
            return createScaledPoint(zInv2, zInv3);
        }
        default:
        {
            throw new IllegalStateException("not a projective coordinate system");
        }
        }
    }

    protected ECPoint createScaledPoint(ECFieldElement sx, ECFieldElement sy)
    {
        return this.getCurve().createRawPoint(getRawXCoord().multiply(sx), getRawYCoord().multiply(sy), this.withCompression);
    }

    public boolean isInfinity()
    {
        return x == null || y == null || (zs.length > 0 && zs[0].isZero());
    }

    public boolean isCompressed()
    {
        return this.withCompression;
    }

    public ECPoint scaleX(ECFieldElement scale)
    {
        return isInfinity()
            ?   this
            :   getCurve().createRawPoint(getRawXCoord().multiply(scale), getRawYCoord(), getRawZCoords(), this.withCompression);
    }

    public ECPoint scaleY(ECFieldElement scale)
    {
        return isInfinity()
            ?   this
            :   getCurve().createRawPoint(getRawXCoord(), getRawYCoord().multiply(scale), getRawZCoords(), this.withCompression);
    }

    public boolean equals(ECPoint other)
    {
        if (null == other)
        {
            return false;
        }

        ECCurve c1 = this.getCurve(), c2 = other.getCurve();
        boolean n1 = (null == c1), n2 = (null == c2);
        boolean i1 = isInfinity(), i2 = other.isInfinity();

        if (i1 || i2)
        {
            return (i1 && i2) && (n1 || n2 || c1.equals(c2));
        }

        ECPoint p1 = this, p2 = other;
        if (n1 && n2)
        {
            // Points with null curve are in affine form, so already normalized
        }
        else if (n1)
        {
            p2 = p2.normalize();
        }
        else if (n2)
        {
            p1 = p1.normalize();
        }
        else if (!c1.equals(c2))
        {
            return false;
        }
        else
        {
            // TODO Consider just requiring already normalized, to avoid silent performance degradation

            ECPoint[] points = new ECPoint[]{ this, c1.importPoint(p2) };

            // TODO This is a little strong, really only requires coZNormalizeAll to get Zs equal
            c1.normalizeAll(points);

            p1 = points[0];
            p2 = points[1];
        }

        return p1.getXCoord().equals(p2.getXCoord()) && p1.getYCoord().equals(p2.getYCoord());
    }

    public boolean equals(Object other)
    {
        if (other == this)
        {
            return true;
        }

        if (!(other instanceof ECPoint))
        {
            return false;
        }

        return equals((ECPoint)other);
    }

    public int hashCode()
    {
        ECCurve c = this.getCurve();
        int hc = (null == c) ? 0 : ~c.hashCode();

        if (!this.isInfinity())
        {
            // TODO Consider just requiring already normalized, to avoid silent performance degradation

            ECPoint p = normalize();

            hc ^= p.getXCoord().hashCode() * 17;
            hc ^= p.getYCoord().hashCode() * 257;
        }

        return hc;
    }

    public String toString()
    {
        if (this.isInfinity())
        {
            return "INF";
        }

        StringBuffer sb = new StringBuffer();
        sb.append('(');
        sb.append(getRawXCoord());
        sb.append(',');
        sb.append(getRawYCoord());
        for (int i = 0; i < zs.length; ++i)
        {
            sb.append(',');
            sb.append(zs[i]);
        }
        sb.append(')');
        return sb.toString();
    }

    public byte[] getEncoded()
    {
        return getEncoded(this.withCompression);
    }

    /**
     * return the field element encoded with point compression. (S 4.3.6)
     */
    public byte[] getEncoded(boolean compressed)
    {
        if (this.isInfinity())
        {
            return new byte[1];
        }

        ECPoint normed = normalize();

        byte[] X = normed.getXCoord().getEncoded();

        if (compressed)
        {
            byte[] PO = new byte[X.length + 1];
            PO[0] = (byte)(normed.getCompressionYTilde() ? 0x03 : 0x02);
            System.arraycopy(X, 0, PO, 1, X.length);
            return PO;
        }

        byte[] Y = normed.getYCoord().getEncoded();

        byte[] PO = new byte[X.length + Y.length + 1];
        PO[0] = 0x04;
        System.arraycopy(X, 0, PO, 1, X.length);
        System.arraycopy(Y, 0, PO, X.length + 1, Y.length);
        return PO;
    }

    protected abstract boolean getCompressionYTilde();

    public abstract ECPoint add(ECPoint b);

    public abstract ECPoint negate();

    public abstract ECPoint subtract(ECPoint b);

    public ECPoint timesPow2(int e)
    {
        if (e < 0)
        {
            throw new IllegalArgumentException("'e' cannot be negative");
        }

        ECPoint p = this;
        while (--e >= 0)
        {
            p = p.twice();
        }
        return p;
    }

    public abstract ECPoint twice();

    public ECPoint twicePlus(ECPoint b)
    {
        return twice().add(b);
    }

    public ECPoint threeTimes()
    {
        return twicePlus(this);
    }

    /**
     * Multiplies this <code>ECPoint</code> by the given number.
     * @param k The multiplicator.
     * @return <code>k * this</code>.
     */
    public ECPoint multiply(BigInteger k)
    {
        return this.getCurve().getMultiplier().multiply(this, k);
    }

    /**
     * Elliptic curve points over Fp
     */
    public static class Fp extends ECPoint
    {
        /**
         * Create a point which encodes with point compression.
         * 
         * @param curve the curve to use
         * @param x affine x co-ordinate
         * @param y affine y co-ordinate
         * 
         * @deprecated Use ECCurve.createPoint to construct points
         */
        public Fp(ECCurve curve, ECFieldElement x, ECFieldElement y)
        {
            this(curve, x, y, false);
        }

        /**
         * Create a point that encodes with or without point compresion.
         * 
         * @param curve the curve to use
         * @param x affine x co-ordinate
         * @param y affine y co-ordinate
         * @param withCompression if true encode with point compression
         * 
         * @deprecated per-point compression property will be removed, refer {@link #getEncoded(boolean)}
         */
        public Fp(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
        {
            super(curve, x, y);

            if ((x == null) != (y == null))
            {
                throw new IllegalArgumentException("Exactly one of the field elements is null");
            }

            this.withCompression = withCompression;
        }

        Fp(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
        {
            super(curve, x, y, zs);

            this.withCompression = withCompression;
        }

        protected ECPoint detach()
        {
            return new ECPoint.Fp(null, getAffineXCoord(), getAffineYCoord());
        }

        protected boolean getCompressionYTilde()
        {
            return this.getAffineYCoord().testBitZero();
        }

        public ECFieldElement getZCoord(int index)
        {
            if (index == 1 && ECCurve.COORD_JACOBIAN_MODIFIED == this.getCurveCoordinateSystem())
            {
                return getJacobianModifiedW();
            }

            return super.getZCoord(index);
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
            int coord = curve.getCoordinateSystem();

            ECFieldElement X1 = this.x, Y1 = this.y;
            ECFieldElement X2 = b.x, Y2 = b.y;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                ECFieldElement dx = X2.subtract(X1), dy = Y2.subtract(Y1);

                if (dx.isZero())
                {
                    if (dy.isZero())
                    {
                        // this == b, i.e. this must be doubled
                        return twice();
                    }

                    // this == -b, i.e. the result is the point at infinity
                    return curve.getInfinity();
                }

                ECFieldElement gamma = dy.divide(dx);
                ECFieldElement X3 = gamma.square().subtract(X1).subtract(X2);
                ECFieldElement Y3 = gamma.multiply(X1.subtract(X3)).subtract(Y1);

                return new ECPoint.Fp(curve, X3, Y3, this.withCompression);
            }

            case ECCurve.COORD_HOMOGENEOUS:
            {
                ECFieldElement Z1 = this.zs[0];
                ECFieldElement Z2 = b.zs[0];

                boolean Z1IsOne = Z1.isOne();
                boolean Z2IsOne = Z2.isOne();

                ECFieldElement u1 = Z1IsOne ? Y2 : Y2.multiply(Z1);
                ECFieldElement u2 = Z2IsOne ? Y1 : Y1.multiply(Z2);
                ECFieldElement u = u1.subtract(u2);
                ECFieldElement v1 = Z1IsOne ? X2 : X2.multiply(Z1);
                ECFieldElement v2 = Z2IsOne ? X1 : X1.multiply(Z2);
                ECFieldElement v = v1.subtract(v2);

                // Check if b == this or b == -this
                if (v.isZero())
                {
                    if (u.isZero())
                    {
                        // this == b, i.e. this must be doubled
                        return this.twice();
                    }

                    // this == -b, i.e. the result is the point at infinity
                    return curve.getInfinity();
                }

                // TODO Optimize for when w == 1
                ECFieldElement w = Z1IsOne ? Z2 : Z2IsOne ? Z1 : Z1.multiply(Z2);
                ECFieldElement vSquared = v.square();
                ECFieldElement vCubed = vSquared.multiply(v);
                ECFieldElement vSquaredV2 = vSquared.multiply(v2);
                ECFieldElement A = u.square().multiply(w).subtract(vCubed).subtract(two(vSquaredV2));

                ECFieldElement X3 = v.multiply(A);
                ECFieldElement Y3 = vSquaredV2.subtract(A).multiplyMinusProduct(u, u2, vCubed);
                ECFieldElement Z3 = vCubed.multiply(w);

                return new ECPoint.Fp(curve, X3, Y3, new ECFieldElement[]{ Z3 }, this.withCompression);
            }

            case ECCurve.COORD_JACOBIAN:
            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                ECFieldElement Z1 = this.zs[0];
                ECFieldElement Z2 = b.zs[0];

                boolean Z1IsOne = Z1.isOne();

                ECFieldElement X3, Y3, Z3, Z3Squared = null;

                if (!Z1IsOne && Z1.equals(Z2))
                {
                    // TODO Make this available as public method coZAdd?

                    ECFieldElement dx = X1.subtract(X2), dy = Y1.subtract(Y2);
                    if (dx.isZero())
                    {
                        if (dy.isZero())
                        {
                            return twice();
                        }
                        return curve.getInfinity();
                    }

                    ECFieldElement C = dx.square();
                    ECFieldElement W1 = X1.multiply(C), W2 = X2.multiply(C);
                    ECFieldElement A1 = W1.subtract(W2).multiply(Y1);

                    X3 = dy.square().subtract(W1).subtract(W2);
                    Y3 = W1.subtract(X3).multiply(dy).subtract(A1);
                    Z3 = dx;

                    if (Z1IsOne)
                    {
                        Z3Squared = C;
                    }
                    else
                    {
                        Z3 = Z3.multiply(Z1);
                    }
                }
                else
                {
                    ECFieldElement Z1Squared, U2, S2;
                    if (Z1IsOne)
                    {
                        Z1Squared = Z1; U2 = X2; S2 = Y2;
                    }
                    else
                    {
                        Z1Squared = Z1.square();
                        U2 = Z1Squared.multiply(X2);
                        ECFieldElement Z1Cubed = Z1Squared.multiply(Z1);
                        S2 = Z1Cubed.multiply(Y2);
                    }

                    boolean Z2IsOne = Z2.isOne();
                    ECFieldElement Z2Squared, U1, S1;
                    if (Z2IsOne)
                    {
                        Z2Squared = Z2; U1 = X1; S1 = Y1;
                    }
                    else
                    {
                        Z2Squared = Z2.square();
                        U1 = Z2Squared.multiply(X1); 
                        ECFieldElement Z2Cubed = Z2Squared.multiply(Z2);
                        S1 = Z2Cubed.multiply(Y1);
                    }

                    ECFieldElement H = U1.subtract(U2);
                    ECFieldElement R = S1.subtract(S2);
    
                    // Check if b == this or b == -this
                    if (H.isZero())
                    {
                        if (R.isZero())
                        {
                            // this == b, i.e. this must be doubled
                            return this.twice();
                        }
    
                        // this == -b, i.e. the result is the point at infinity
                        return curve.getInfinity();
                    }
    
                    ECFieldElement HSquared = H.square();
                    ECFieldElement G = HSquared.multiply(H);
                    ECFieldElement V = HSquared.multiply(U1);
    
                    X3 = R.square().add(G).subtract(two(V));
                    Y3 = V.subtract(X3).multiplyMinusProduct(R, G, S1);

                    Z3 = H;
                    if (!Z1IsOne)
                    {
                        Z3 = Z3.multiply(Z1);
                    }
                    if (!Z2IsOne)
                    {
                        Z3 = Z3.multiply(Z2);
                    }
    
                    // Alternative calculation of Z3 using fast square
    //                X3 = four(X3);
    //                Y3 = eight(Y3);
    //                Z3 = doubleProductFromSquares(Z1, Z2, Z1Squared, Z2Squared).multiply(H);
                    
                    if (Z3 == H)
                    {
                        Z3Squared = HSquared;
                    }
                }

                ECFieldElement[] zs;
                if (coord == ECCurve.COORD_JACOBIAN_MODIFIED)
                {
                    // TODO If the result will only be used in a subsequent addition, we don't need W3
                    ECFieldElement W3 = calculateJacobianModifiedW(Z3, Z3Squared);

                    zs = new ECFieldElement[]{ Z3, W3 };
                }
                else
                {
                    zs = new ECFieldElement[]{ Z3 };
                }

                return new ECPoint.Fp(curve, X3, Y3, zs, this.withCompression);
            }

            default:
            {
                throw new IllegalStateException("unsupported coordinate system");
            }
            }
        }

        // B.3 pg 62
        public ECPoint twice()
        {
            if (this.isInfinity())
            {
                return this;
            }

            ECCurve curve = this.getCurve();

            ECFieldElement Y1 = this.y;
            if (Y1.isZero()) 
            {
                return curve.getInfinity();
            }

            int coord = curve.getCoordinateSystem();

            ECFieldElement X1 = this.x;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                ECFieldElement X1Squared = X1.square();
                ECFieldElement gamma = three(X1Squared).add(this.getCurve().getA()).divide(two(Y1));
                ECFieldElement X3 = gamma.square().subtract(two(X1));
                ECFieldElement Y3 = gamma.multiply(X1.subtract(X3)).subtract(Y1);
    
                return new ECPoint.Fp(curve, X3, Y3, this.withCompression);
            }

            case ECCurve.COORD_HOMOGENEOUS:
            {
                ECFieldElement Z1 = this.zs[0];

                boolean Z1IsOne = Z1.isOne();

                // TODO Optimize for small negative a4 and -3
                ECFieldElement w = curve.getA();
                if (!w.isZero() && !Z1IsOne)
                {
                    w = w.multiply(Z1.square());
                }
                w = w.add(three(X1.square()));
                
                ECFieldElement s = Z1IsOne ? Y1 : Y1.multiply(Z1);
                ECFieldElement t = Z1IsOne ? Y1.square() : s.multiply(Y1);
                ECFieldElement B = X1.multiply(t);
                ECFieldElement _4B = four(B);
                ECFieldElement h = w.square().subtract(two(_4B));

                ECFieldElement _2s = two(s);
                ECFieldElement X3 = h.multiply(_2s);
                ECFieldElement _2t = two(t);
                ECFieldElement Y3 = _4B.subtract(h).multiply(w).subtract(two(_2t.square()));
                ECFieldElement _4sSquared = Z1IsOne ? two(_2t) : _2s.square();
                ECFieldElement Z3 = two(_4sSquared).multiply(s);

                return new ECPoint.Fp(curve, X3, Y3, new ECFieldElement[]{ Z3 }, this.withCompression);
            }

            case ECCurve.COORD_JACOBIAN:
            {
                ECFieldElement Z1 = this.zs[0];

                boolean Z1IsOne = Z1.isOne();

                ECFieldElement Y1Squared = Y1.square();
                ECFieldElement T = Y1Squared.square();

                ECFieldElement a4 = curve.getA();
                ECFieldElement a4Neg = a4.negate();

                ECFieldElement M, S;
                if (a4Neg.toBigInteger().equals(BigInteger.valueOf(3)))
                {
                    ECFieldElement Z1Squared = Z1IsOne ? Z1 : Z1.square();
                    M = three(X1.add(Z1Squared).multiply(X1.subtract(Z1Squared)));
                    S = four(Y1Squared.multiply(X1));
                }
                else
                {
                    ECFieldElement X1Squared = X1.square();
                    M = three(X1Squared);
                    if (Z1IsOne)
                    {
                        M = M.add(a4);
                    }
                    else if (!a4.isZero())
                    {
                        ECFieldElement Z1Squared = Z1IsOne ? Z1 : Z1.square();
                        ECFieldElement Z1Pow4 = Z1Squared.square();
                        if (a4Neg.bitLength() < a4.bitLength())
                        {
                            M = M.subtract(Z1Pow4.multiply(a4Neg));
                        }
                        else
                        {
                            M = M.add(Z1Pow4.multiply(a4));
                        }
                    }
//                  S = two(doubleProductFromSquares(X1, Y1Squared, X1Squared, T));
                    S = four(X1.multiply(Y1Squared));
                }

                ECFieldElement X3 = M.square().subtract(two(S));
                ECFieldElement Y3 = S.subtract(X3).multiply(M).subtract(eight(T));

                ECFieldElement Z3 = two(Y1);
                if (!Z1IsOne)
                {
                    Z3 = Z3.multiply(Z1);
                }

                // Alternative calculation of Z3 using fast square
//                ECFieldElement Z3 = doubleProductFromSquares(Y1, Z1, Y1Squared, Z1Squared);

                return new ECPoint.Fp(curve, X3, Y3, new ECFieldElement[]{ Z3 }, this.withCompression);
            }

            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                return twiceJacobianModified(true);
            }

            default:
            {
                throw new IllegalStateException("unsupported coordinate system");
            }
            }
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

            ECCurve curve = this.getCurve();
            int coord = curve.getCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                ECFieldElement X1 = this.x;
                ECFieldElement X2 = b.x, Y2 = b.y;

                ECFieldElement dx = X2.subtract(X1), dy = Y2.subtract(Y1);

                if (dx.isZero())
                {
                    if (dy.isZero())
                    {
                        // this == b i.e. the result is 3P
                        return threeTimes();
                    }

                    // this == -b, i.e. the result is P
                    return this;
                }

                /*
                 * Optimized calculation of 2P + Q, as described in "Trading Inversions for
                 * Multiplications in Elliptic Curve Cryptography", by Ciet, Joye, Lauter, Montgomery.
                 */

                ECFieldElement X = dx.square(), Y = dy.square();
                ECFieldElement d = X.multiply(two(X1).add(X2)).subtract(Y);
                if (d.isZero())
                {
                    return curve.getInfinity();
                }

                ECFieldElement D = d.multiply(dx);
                ECFieldElement I = D.invert();
                ECFieldElement L1 = d.multiply(I).multiply(dy);
                ECFieldElement L2 = two(Y1).multiply(X).multiply(dx).multiply(I).subtract(L1);
                ECFieldElement X4 = (L2.subtract(L1)).multiply(L1.add(L2)).add(X2);
                ECFieldElement Y4 = (X1.subtract(X4)).multiply(L2).subtract(Y1);

                return new ECPoint.Fp(curve, X4, Y4, this.withCompression);
            }
            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                return twiceJacobianModified(false).add(b);
            }
            default:
            {
                return twice().add(b);
            }
            }
        }

        public ECPoint threeTimes()
        {
            if (this.isInfinity())
            {
                return this;
            }

            ECFieldElement Y1 = this.y;
            if (Y1.isZero())
            {
                return this;
            }

            ECCurve curve = this.getCurve();
            int coord = curve.getCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                ECFieldElement X1 = this.x;

                ECFieldElement _2Y1 = two(Y1); 
                ECFieldElement X = _2Y1.square();
                ECFieldElement Z = three(X1.square()).add(this.getCurve().getA());
                ECFieldElement Y = Z.square();

                ECFieldElement d = three(X1).multiply(X).subtract(Y);
                if (d.isZero())
                {
                    return this.getCurve().getInfinity();
                }

                ECFieldElement D = d.multiply(_2Y1); 
                ECFieldElement I = D.invert();
                ECFieldElement L1 = d.multiply(I).multiply(Z);
                ECFieldElement L2 = X.square().multiply(I).subtract(L1);

                ECFieldElement X4 = (L2.subtract(L1)).multiply(L1.add(L2)).add(X1);
                ECFieldElement Y4 = (X1.subtract(X4)).multiply(L2).subtract(Y1); 
                return new ECPoint.Fp(curve, X4, Y4, this.withCompression);
            }
            case ECCurve.COORD_JACOBIAN_MODIFIED:
            {
                return twiceJacobianModified(false).add(this);
            }
            default:
            {
                // NOTE: Be careful about recursions between twicePlus and threeTimes
                return twice().add(this);
            }
            }
        }

        public ECPoint timesPow2(int e)
        {
            if (e < 0)
            {
                throw new IllegalArgumentException("'e' cannot be negative");
            }
            if (e == 0 || this.isInfinity())
            {
                return this;
            }
            if (e == 1)
            {
                return twice();
            }

            ECCurve curve = this.getCurve();

            ECFieldElement Y1 = this.y;
            if (Y1.isZero()) 
            {
                return curve.getInfinity();
            }

            int coord = curve.getCoordinateSystem();

            ECFieldElement W1 = curve.getA();
            ECFieldElement X1 = this.x;
            ECFieldElement Z1 = this.zs.length < 1 ? curve.fromBigInteger(ECConstants.ONE) : this.zs[0];

            if (!Z1.isOne())
            {
                switch (coord)
                {
                case ECCurve.COORD_HOMOGENEOUS:
                    ECFieldElement Z1Sq = Z1.square();
                    X1 = X1.multiply(Z1);
                    Y1 = Y1.multiply(Z1Sq);
                    W1 = calculateJacobianModifiedW(Z1, Z1Sq);
                    break;
                case ECCurve.COORD_JACOBIAN:
                    W1 = calculateJacobianModifiedW(Z1, null);
                    break;
                case ECCurve.COORD_JACOBIAN_MODIFIED:
                    W1 = getJacobianModifiedW();
                    break;
                }
            }

            for (int i = 0; i < e; ++i)
            {
                if (Y1.isZero()) 
                {
                    return curve.getInfinity();
                }

                ECFieldElement X1Squared = X1.square();
                ECFieldElement M = three(X1Squared);
                ECFieldElement _2Y1 = two(Y1);
                ECFieldElement _2Y1Squared = _2Y1.multiply(Y1);
                ECFieldElement S = two(X1.multiply(_2Y1Squared));
                ECFieldElement _4T = _2Y1Squared.square();
                ECFieldElement _8T = two(_4T);

                if (!W1.isZero())
                {
                    M = M.add(W1);
                    W1 = two(_8T.multiply(W1));
                }

                X1 = M.square().subtract(two(S));
                Y1 = M.multiply(S.subtract(X1)).subtract(_8T);
                Z1 = Z1.isOne() ? _2Y1 : _2Y1.multiply(Z1);
            }

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
                ECFieldElement zInv = Z1.invert(), zInv2 = zInv.square(), zInv3 = zInv2.multiply(zInv);
                return new Fp(curve, X1.multiply(zInv2), Y1.multiply(zInv3), this.withCompression);
            case ECCurve.COORD_HOMOGENEOUS:
                X1 = X1.multiply(Z1);
                Z1 = Z1.multiply(Z1.square());
                return new Fp(curve, X1, Y1, new ECFieldElement[]{ Z1 }, this.withCompression);
            case ECCurve.COORD_JACOBIAN:
                return new Fp(curve, X1, Y1, new ECFieldElement[]{ Z1 }, this.withCompression);
            case ECCurve.COORD_JACOBIAN_MODIFIED:
                return new Fp(curve, X1, Y1, new ECFieldElement[]{ Z1, W1 }, this.withCompression);
            default:
                throw new IllegalStateException("unsupported coordinate system");
            }
        }

        protected ECFieldElement two(ECFieldElement x)
        {
            return x.add(x);
        }

        protected ECFieldElement three(ECFieldElement x)
        {
            return two(x).add(x);
        }

        protected ECFieldElement four(ECFieldElement x)
        {
            return two(two(x));
        }

        protected ECFieldElement eight(ECFieldElement x)
        {
            return four(two(x));
        }

        protected ECFieldElement doubleProductFromSquares(ECFieldElement a, ECFieldElement b,
            ECFieldElement aSquared, ECFieldElement bSquared)
        {
            /*
             * NOTE: If squaring in the field is faster than multiplication, then this is a quicker
             * way to calculate 2.A.B, if A^2 and B^2 are already known.
             */
            return a.add(b).square().subtract(aSquared).subtract(bSquared);
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

            ECCurve curve = this.getCurve();
            int coord = curve.getCoordinateSystem();

            if (ECCurve.COORD_AFFINE != coord)
            {
                return new ECPoint.Fp(curve, this.x, this.y.negate(), this.zs, this.withCompression);
            }

            return new ECPoint.Fp(curve, this.x, this.y.negate(), this.withCompression);
        }

        protected ECFieldElement calculateJacobianModifiedW(ECFieldElement Z, ECFieldElement ZSquared)
        {
            ECFieldElement a4 = this.getCurve().getA();
            if (a4.isZero() || Z.isOne())
            {
                return a4;
            }

            if (ZSquared == null)
            {
                ZSquared = Z.square();
            }

            ECFieldElement W = ZSquared.square();
            ECFieldElement a4Neg = a4.negate();
            if (a4Neg.bitLength() < a4.bitLength())
            {
                W = W.multiply(a4Neg).negate();
            }
            else
            {
                W = W.multiply(a4);
            }
            return W;
        }

        protected ECFieldElement getJacobianModifiedW()
        {
            ECFieldElement W = this.zs[1];
            if (W == null)
            {
                // NOTE: Rarely, twicePlus will result in the need for a lazy W1 calculation here
                this.zs[1] = W = calculateJacobianModifiedW(this.zs[0], null);
            }
            return W;
        }

        protected ECPoint.Fp twiceJacobianModified(boolean calculateW)
        {
            ECFieldElement X1 = this.x, Y1 = this.y, Z1 = this.zs[0], W1 = getJacobianModifiedW();

            ECFieldElement X1Squared = X1.square();
            ECFieldElement M = three(X1Squared).add(W1);
            ECFieldElement _2Y1 = two(Y1);
            ECFieldElement _2Y1Squared = _2Y1.multiply(Y1);
            ECFieldElement S = two(X1.multiply(_2Y1Squared));
            ECFieldElement X3 = M.square().subtract(two(S));
            ECFieldElement _4T = _2Y1Squared.square();
            ECFieldElement _8T = two(_4T);
            ECFieldElement Y3 = M.multiply(S.subtract(X3)).subtract(_8T);
            ECFieldElement W3 = calculateW ? two(_8T.multiply(W1)) : null;
            ECFieldElement Z3 = Z1.isOne() ? _2Y1 : _2Y1.multiply(Z1);

            return new ECPoint.Fp(this.getCurve(), X3, Y3, new ECFieldElement[]{ Z3, W3 }, this.withCompression);
        }
    }

    /**
     * Elliptic curve points over F2m
     */
    public static class F2m extends ECPoint
    {
        /**
         * @param curve base curve
         * @param x x point
         * @param y y point
         * 
         * @deprecated Use ECCurve.createPoint to construct points
         */
        public F2m(ECCurve curve, ECFieldElement x, ECFieldElement y)
        {
            this(curve, x, y, false);
        }
        
        /**
         * @param curve base curve
         * @param x x point
         * @param y y point
         * @param withCompression true if encode with point compression.
         * 
         * @deprecated per-point compression property will be removed, refer {@link #getEncoded(boolean)}
         */
        public F2m(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
        {
            super(curve, x, y);

            if ((x == null) != (y == null))
            {
                throw new IllegalArgumentException("Exactly one of the field elements is null");
            }

            if (x != null)
            {
                // Check if x and y are elements of the same field
                ECFieldElement.F2m.checkFieldElements(this.x, this.y);

                // Check if x and a are elements of the same field
                if (curve != null)
                {
                    ECFieldElement.F2m.checkFieldElements(this.x, this.curve.getA());
                }
            }

            this.withCompression = withCompression;

//            checkCurveEquation();
        }

        F2m(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
        {
            super(curve, x, y, zs);

            this.withCompression = withCompression;

//            checkCurveEquation();
        }

        protected ECPoint detach()
        {
            return new ECPoint.F2m(null, getAffineXCoord(), getAffineYCoord());
        }

        public ECFieldElement getYCoord()
        {
            int coord = this.getCurveCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_LAMBDA_AFFINE:
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                ECFieldElement X = x, L = y;

                if (this.isInfinity() || X.isZero())
                {
                    return L;
                }

                // Y is actually Lambda (X + Y/X) here; convert to affine value on the fly
                ECFieldElement Y = L.add(X).multiply(X);
                if (ECCurve.COORD_LAMBDA_PROJECTIVE == coord)
                {
                    ECFieldElement Z = zs[0];
                    if (!Z.isOne())
                    {
                        Y = Y.divide(Z);
                    }
                }
                return Y;
            }
            default:
            {
                return y;
            }
            }
        }

        public ECPoint scaleX(ECFieldElement scale)
        {
            if (this.isInfinity())
            {
                return this;
            }

            int coord = this.getCurveCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_LAMBDA_AFFINE:
            {
                // Y is actually Lambda (X + Y/X) here
                ECFieldElement X = getRawXCoord(), L = getRawYCoord();

                ECFieldElement X2 = X.multiply(scale);
                ECFieldElement L2 = L.add(X).divide(scale).add(X2);

                return getCurve().createRawPoint(X, L2, getRawZCoords(), this.withCompression);
            }
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                // Y is actually Lambda (X + Y/X) here
                ECFieldElement X = getRawXCoord(), L = getRawYCoord(), Z = getRawZCoords()[0];

                // We scale the Z coordinate also, to avoid an inversion
                ECFieldElement X2 = X.multiply(scale.square());
                ECFieldElement L2 = L.add(X).add(X2);
                ECFieldElement Z2 = Z.multiply(scale);

                return getCurve().createRawPoint(X2, L2, new ECFieldElement[]{ Z2 }, this.withCompression);
            }
            default:
            {
                return super.scaleX(scale);
            }
            }
        }

        public ECPoint scaleY(ECFieldElement scale)
        {
            if (this.isInfinity())
            {
                return this;
            }

            int coord = this.getCurveCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_LAMBDA_AFFINE:
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                ECFieldElement X = getRawXCoord(), L = getRawYCoord();

                // Y is actually Lambda (X + Y/X) here
                ECFieldElement L2 = L.add(X).multiply(scale).add(X);

                return getCurve().createRawPoint(X, L2, getRawZCoords(), this.withCompression);
            }
            default:
            {
                return super.scaleY(scale);
            }
            }
        }

        protected boolean getCompressionYTilde()
        {
            ECFieldElement X = this.getRawXCoord();
            if (X.isZero())
            {
                return false;
            }

            ECFieldElement Y = this.getRawYCoord();

            switch (this.getCurveCoordinateSystem())
            {
            case ECCurve.COORD_LAMBDA_AFFINE:
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                // Y is actually Lambda (X + Y/X) here
                return Y.testBitZero() != X.testBitZero();
            }
            default:
            {
                return Y.divide(X).testBitZero();
            }
            }
        }

        /**
         * Check, if two <code>ECPoint</code>s can be added or subtracted.
         * @param a The first <code>ECPoint</code> to check.
         * @param b The second <code>ECPoint</code> to check.
         * @throws IllegalArgumentException if <code>a</code> and <code>b</code>
         * cannot be added.
         */
        private static void checkPoints(ECPoint a, ECPoint b)
        {
            // Check, if points are on the same curve
            if (a.curve != b.curve)
            {
                throw new IllegalArgumentException("Only points on the same "
                        + "curve can be added or subtracted");
            }

//            ECFieldElement.F2m.checkFieldElements(a.x, b.x);
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#add(org.bouncycastle.math.ec.ECPoint)
         */
        public ECPoint add(ECPoint b)
        {
            checkPoints(this, b);
            return addSimple((ECPoint.F2m)b);
        }

        /**
         * Adds another <code>ECPoints.F2m</code> to <code>this</code> without
         * checking if both points are on the same curve. Used by multiplication
         * algorithms, because there all points are a multiple of the same point
         * and hence the checks can be omitted.
         * @param b The other <code>ECPoints.F2m</code> to add to
         * <code>this</code>.
         * @return <code>this + b</code>
         */
        public ECPoint.F2m addSimple(ECPoint.F2m b)
        {
            if (this.isInfinity())
            {
                return b;
            }
            if (b.isInfinity())
            {
                return this;
            }

            ECCurve curve = this.getCurve();
            int coord = curve.getCoordinateSystem();

            ECFieldElement X1 = this.x;
            ECFieldElement X2 = b.x;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                ECFieldElement Y1 = this.y;
                ECFieldElement Y2 = b.y;

                ECFieldElement dx = X1.add(X2), dy = Y1.add(Y2);
                if (dx.isZero())
                {
                    if (dy.isZero())
                    {
                        return (ECPoint.F2m)twice();
                    }

                    return (ECPoint.F2m)curve.getInfinity();
                }

                ECFieldElement L = dy.divide(dx);

                ECFieldElement X3 = L.square().add(L).add(dx).add(curve.getA());
                ECFieldElement Y3 = L.multiply(X1.add(X3)).add(X3).add(Y1);

                return new ECPoint.F2m(curve, X3, Y3, this.withCompression);
            }
            case ECCurve.COORD_HOMOGENEOUS:
            {
                ECFieldElement Y1 = this.y, Z1 = this.zs[0];
                ECFieldElement Y2 = b.y, Z2 = b.zs[0];

                boolean Z2IsOne = Z2.isOne();

                ECFieldElement U1 = Z1.multiply(Y2);
                ECFieldElement U2 = Z2IsOne ? Y1 : Y1.multiply(Z2);
                ECFieldElement U = U1.add(U2);
                ECFieldElement V1 = Z1.multiply(X2);
                ECFieldElement V2 = Z2IsOne ? X1 : X1.multiply(Z2);
                ECFieldElement V = V1.add(V2);

                if (V.isZero())
                {
                    if (U.isZero())
                    {
                        return (ECPoint.F2m)twice();
                    }

                    return (ECPoint.F2m)curve.getInfinity();
                }

                ECFieldElement VSq = V.square();
                ECFieldElement VCu = VSq.multiply(V);
                ECFieldElement W = Z2IsOne ? Z1 : Z1.multiply(Z2);
                ECFieldElement uv = U.add(V);
                ECFieldElement A = uv.multiplyPlusProduct(U, VSq, curve.getA()).multiply(W).add(VCu);

                ECFieldElement X3 = V.multiply(A);
                ECFieldElement VSqZ2 = Z2IsOne ? VSq : VSq.multiply(Z2);
                ECFieldElement Y3 = U.multiplyPlusProduct(X1, V, Y1).multiplyPlusProduct(VSqZ2, uv, A);
                ECFieldElement Z3 = VCu.multiply(W);

                return new ECPoint.F2m(curve, X3, Y3, new ECFieldElement[]{ Z3 }, this.withCompression);
            }
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                if (X1.isZero())
                {
                    if (X2.isZero())
                    {
                        return (ECPoint.F2m)curve.getInfinity();
                    }

                    return b.addSimple(this);
                }

                ECFieldElement L1 = this.y, Z1 = this.zs[0];
                ECFieldElement L2 = b.y, Z2 = b.zs[0];

                boolean Z1IsOne = Z1.isOne();
                ECFieldElement U2 = X2, S2 = L2;
                if (!Z1IsOne)
                {
                    U2 = U2.multiply(Z1);
                    S2 = S2.multiply(Z1);
                }

                boolean Z2IsOne = Z2.isOne();
                ECFieldElement U1 = X1, S1 = L1;
                if (!Z2IsOne)
                {
                    U1 = U1.multiply(Z2);
                    S1 = S1.multiply(Z2);
                }

                ECFieldElement A = S1.add(S2);
                ECFieldElement B = U1.add(U2);

                if (B.isZero())
                {
                    if (A.isZero())
                    {
                        return (ECPoint.F2m)twice();
                    }

                    return (ECPoint.F2m)curve.getInfinity();
                }

                ECFieldElement X3, L3, Z3;
                if (X2.isZero())
                {
                    // TODO This can probably be optimized quite a bit
                    ECPoint p = this.normalize();
                    X1 = p.getXCoord();
                    ECFieldElement Y1 = p.getYCoord();

                    ECFieldElement Y2 = L2;
                    ECFieldElement L = Y1.add(Y2).divide(X1);

                    X3 = L.square().add(L).add(X1).add(curve.getA());
                    if (X3.isZero())
                    {
                        return new ECPoint.F2m(curve, X3, curve.getB().sqrt(), this.withCompression);
                    }

                    ECFieldElement Y3 = L.multiply(X1.add(X3)).add(X3).add(Y1);
                    L3 = Y3.divide(X3).add(X3);
                    Z3 = curve.fromBigInteger(ECConstants.ONE);
                }
                else
                {
                    B = B.square();
    
                    ECFieldElement AU1 = A.multiply(U1);
                    ECFieldElement AU2 = A.multiply(U2);

                    X3 = AU1.multiply(AU2);
                    if (X3.isZero())
                    {
                        return new ECPoint.F2m(curve, X3, curve.getB().sqrt(), this.withCompression);
                    }

                    ECFieldElement ABZ2 = A.multiply(B);
                    if (!Z2IsOne)
                    {
                        ABZ2 = ABZ2.multiply(Z2);
                    }

                    L3 = AU2.add(B).squarePlusProduct(ABZ2, L1.add(Z1));

                    Z3 = ABZ2;
                    if (!Z1IsOne)
                    {
                        Z3 = Z3.multiply(Z1);
                    }
                }

                return new ECPoint.F2m(curve, X3, L3, new ECFieldElement[]{ Z3 }, this.withCompression);
            }
            default:
            {
                throw new IllegalStateException("unsupported coordinate system");
            }
            }
        }

        /* (non-Javadoc)
         * @see org.bouncycastle.math.ec.ECPoint#subtract(org.bouncycastle.math.ec.ECPoint)
         */
        public ECPoint subtract(ECPoint b)
        {
            checkPoints(this, b);
            return subtractSimple((ECPoint.F2m)b);
        }

        /**
         * Subtracts another <code>ECPoints.F2m</code> from <code>this</code>
         * without checking if both points are on the same curve. Used by
         * multiplication algorithms, because there all points are a multiple
         * of the same point and hence the checks can be omitted.
         * @param b The other <code>ECPoints.F2m</code> to subtract from
         * <code>this</code>.
         * @return <code>this - b</code>
         */
        public ECPoint.F2m subtractSimple(ECPoint.F2m b)
        {
            if (b.isInfinity())
            {
                return this;
            }

            // Add -b
            return addSimple((ECPoint.F2m)b.negate());
        }

        public ECPoint.F2m tau()
        {
            if (this.isInfinity())
            {
                return this;
            }

            ECCurve curve = this.getCurve();
            int coord = curve.getCoordinateSystem();

            ECFieldElement X1 = this.x;

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            case ECCurve.COORD_LAMBDA_AFFINE:
            {
                ECFieldElement Y1 = this.y;
                return new ECPoint.F2m(curve, X1.square(), Y1.square(), this.withCompression);
            }
            case ECCurve.COORD_HOMOGENEOUS:
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                ECFieldElement Y1 = this.y, Z1 = this.zs[0];
                return new ECPoint.F2m(curve, X1.square(), Y1.square(), new ECFieldElement[]{ Z1.square() }, this.withCompression);
            }
            default:
            {
                throw new IllegalStateException("unsupported coordinate system");
            }
            }
        }

        public ECPoint twice()
        {
            if (this.isInfinity()) 
            {
                return this;
            }

            ECCurve curve = this.getCurve();

            ECFieldElement X1 = this.x;
            if (X1.isZero()) 
            {
                // A point with X == 0 is it's own additive inverse
                return curve.getInfinity();
            }

            int coord = curve.getCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_AFFINE:
            {
                ECFieldElement Y1 = this.y;

                ECFieldElement L1 = Y1.divide(X1).add(X1);

                ECFieldElement X3 = L1.square().add(L1).add(curve.getA());
                ECFieldElement Y3 = X1.squarePlusProduct(X3, L1.addOne());

                return new ECPoint.F2m(curve, X3, Y3, this.withCompression);
            }
            case ECCurve.COORD_HOMOGENEOUS:
            {
                ECFieldElement Y1 = this.y, Z1 = this.zs[0];

                boolean Z1IsOne = Z1.isOne();
                ECFieldElement X1Z1 = Z1IsOne ? X1 : X1.multiply(Z1);
                ECFieldElement Y1Z1 = Z1IsOne ? Y1 : Y1.multiply(Z1);

                ECFieldElement X1Sq = X1.square();
                ECFieldElement S = X1Sq.add(Y1Z1);
                ECFieldElement V = X1Z1;
                ECFieldElement vSquared = V.square();
                ECFieldElement sv = S.add(V);
                ECFieldElement h = sv.multiplyPlusProduct(S, vSquared, curve.getA());

                ECFieldElement X3 = V.multiply(h);
                ECFieldElement Y3 = X1Sq.square().multiplyPlusProduct(V, h, sv);
                ECFieldElement Z3 = V.multiply(vSquared);    

                return new ECPoint.F2m(curve, X3, Y3, new ECFieldElement[]{ Z3 }, this.withCompression);
            }
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                ECFieldElement L1 = this.y, Z1 = this.zs[0];

                boolean Z1IsOne = Z1.isOne();
                ECFieldElement L1Z1 = Z1IsOne ? L1 : L1.multiply(Z1);
                ECFieldElement Z1Sq = Z1IsOne ? Z1 : Z1.square();
                ECFieldElement a = curve.getA();
                ECFieldElement aZ1Sq = Z1IsOne ? a : a.multiply(Z1Sq);
                ECFieldElement T = L1.square().add(L1Z1).add(aZ1Sq);
                if (T.isZero())
                {
                    return new ECPoint.F2m(curve, T, curve.getB().sqrt(), withCompression);
                }

                ECFieldElement X3 = T.square();
                ECFieldElement Z3 = Z1IsOne ? T : T.multiply(Z1Sq);

                ECFieldElement b = curve.getB();
                ECFieldElement L3;
                if (b.bitLength() < (curve.getFieldSize() >> 1))
                {
                    ECFieldElement t1 = L1.add(X1).square();
                    ECFieldElement t2;
                    if (b.isOne())
                    {
                        t2 = aZ1Sq.add(Z1Sq).square();
                    }
                    else
                    {
                        // TODO Can be calculated with one square if we pre-compute sqrt(b)
                        t2 = aZ1Sq.squarePlusProduct(b, Z1Sq.square());
                    }
                    L3 = t1.add(T).add(Z1Sq).multiply(t1).add(t2).add(X3);
                    if (a.isZero())
                    {
                        L3 = L3.add(Z3);
                    }
                    else if (!a.isOne())
                    {
                        L3 = L3.add(a.addOne().multiply(Z3));
                    }
                }
                else
                {
                    ECFieldElement X1Z1 = Z1IsOne ? X1 : X1.multiply(Z1);
                    L3 = X1Z1.squarePlusProduct(T, L1Z1).add(X3).add(Z3);
                }

                return new ECPoint.F2m(curve, X3, L3, new ECFieldElement[]{ Z3 }, this.withCompression);
            }
            default:
            {
                throw new IllegalStateException("unsupported coordinate system");
            }
            }
        }

        public ECPoint twicePlus(ECPoint b)
        {
            if (this.isInfinity()) 
            {
                return b;
            }
            if (b.isInfinity())
            {
                return twice();
            }

            ECCurve curve = this.getCurve();

            ECFieldElement X1 = this.x;
            if (X1.isZero()) 
            {
                // A point with X == 0 is it's own additive inverse
                return b;
            }

            int coord = curve.getCoordinateSystem();

            switch (coord)
            {
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                // NOTE: twicePlus() only optimized for lambda-affine argument
                ECFieldElement X2 = b.x, Z2 = b.zs[0];
                if (X2.isZero() || !Z2.isOne())
                {
                    return twice().add(b);
                }

                ECFieldElement L1 = this.y, Z1 = this.zs[0];
                ECFieldElement L2 = b.y;

                ECFieldElement X1Sq = X1.square();
                ECFieldElement L1Sq = L1.square();
                ECFieldElement Z1Sq = Z1.square();
                ECFieldElement L1Z1 = L1.multiply(Z1);

                ECFieldElement T = curve.getA().multiply(Z1Sq).add(L1Sq).add(L1Z1);
                ECFieldElement L2plus1 = L2.addOne();
                ECFieldElement A = curve.getA().add(L2plus1).multiply(Z1Sq).add(L1Sq).multiplyPlusProduct(T, X1Sq, Z1Sq);
                ECFieldElement X2Z1Sq = X2.multiply(Z1Sq);
                ECFieldElement B = X2Z1Sq.add(T).square();

                if (B.isZero())
                {
                    if (A.isZero())
                    {
                        return b.twice();
                    }

                    return curve.getInfinity();
                }

                if (A.isZero())
                {
                    return new ECPoint.F2m(curve, A, curve.getB().sqrt(), withCompression);
                }

                ECFieldElement X3 = A.square().multiply(X2Z1Sq);
                ECFieldElement Z3 = A.multiply(B).multiply(Z1Sq);
                ECFieldElement L3 = A.add(B).square().multiplyPlusProduct(T, L2plus1, Z3);

                return new ECPoint.F2m(curve, X3, L3, new ECFieldElement[]{ Z3 }, this.withCompression);
            }
            default:
            {
                return twice().add(b);
            }
            }
        }

        protected void checkCurveEquation()
        {
            if (this.isInfinity())
            {
                return;
            }

            ECFieldElement Z;
            switch (this.getCurveCoordinateSystem())
            {
            case ECCurve.COORD_LAMBDA_AFFINE:
                Z = curve.fromBigInteger(ECConstants.ONE);
                break;
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
                Z = this.zs[0];
                break;
            default:
                return;
            }

            if (Z.isZero())
            {
                throw new IllegalStateException();
            }

            ECCurve curve = this.getCurve();

            boolean ZIsOne = Z.isOne();
            ECFieldElement ZSq = ZIsOne ? Z : Z.square();

            ECFieldElement X = this.x;
            if (X.isZero())
            {
                // NOTE: For x == 0, we expect the affine-y instead of the lambda-y 
                ECFieldElement Y = this.y;
                if (!Y.square().equals(curve.getB().multiply(ZSq)))
                {
                    throw new IllegalStateException();
                }

                return;
            }

            ECFieldElement A = curve.getA(), B = curve.getB();
            ECFieldElement L = this.y;
            ECFieldElement XSq = X.square();

            ECFieldElement lhs, rhs;
            if (ZIsOne)
            {
                lhs = L.square().add(L).add(A).multiply(XSq);
                rhs = XSq.square().add(B);
            }
            else
            {
                lhs = L.add(Z).multiplyPlusProduct(L, A, ZSq).multiply(XSq);
                // TODO If sqrt(b) is precomputed this can be simplified to a single square
                rhs = XSq.squarePlusProduct(B, ZSq.square());
            }
            
            if (!lhs.equals(rhs))
            {
                throw new IllegalStateException("F2m Lambda-Projective invariant broken");
            }
        }

        public ECPoint negate()
        {
            if (this.isInfinity())
            {
                return this;
            }

            ECFieldElement X = this.x;
            if (X.isZero())
            {
                return this;
            }

            switch (this.getCurveCoordinateSystem())
            {
            case ECCurve.COORD_AFFINE:
            {
                ECFieldElement Y = this.y;
                return new ECPoint.F2m(curve, X, Y.add(X), this.withCompression);
            }
            case ECCurve.COORD_HOMOGENEOUS:
            {
                ECFieldElement Y = this.y, Z = this.zs[0];
                return new ECPoint.F2m(curve, X, Y.add(X), new ECFieldElement[]{ Z }, this.withCompression);
            }
            case ECCurve.COORD_LAMBDA_AFFINE:
            {
                ECFieldElement L = this.y;
                return new ECPoint.F2m(curve, X, L.addOne(), this.withCompression);
            }
            case ECCurve.COORD_LAMBDA_PROJECTIVE:
            {
                // L is actually Lambda (X + Y/X) here
                ECFieldElement L = this.y, Z = this.zs[0];
                return new ECPoint.F2m(curve, X, L.add(Z), new ECFieldElement[]{ Z }, this.withCompression);
            }
            default:
            {
                throw new IllegalStateException("unsupported coordinate system");
            }
            }
        }
    }
}
