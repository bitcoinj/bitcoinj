package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.GLVMultiplier;
import org.bouncycastle.math.ec.endo.GLVTypeBEndomorphism;
import org.bouncycastle.math.ec.endo.GLVTypeBParameters;
import org.bouncycastle.math.field.FiniteFields;
import org.bouncycastle.util.encoders.Hex;

public class SecP224K1Curve extends ECCurve
{
    public static final BigInteger q = new BigInteger(1,
        Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D"));

    private static final int SECP224K1_DEFAULT_COORDS = COORD_JACOBIAN;

    protected SecP224K1Point infinity;

    public SecP224K1Curve()
    {
        super(FiniteFields.getPrimeField(q));

        this.infinity = new SecP224K1Point(this, null, null);

        this.a = fromBigInteger(ECConstants.ZERO);
        this.b = fromBigInteger(BigInteger.valueOf(5));
        this.order = new BigInteger(1, Hex.decode("010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7"));
        this.cofactor = BigInteger.valueOf(1);
        this.coord = SECP224K1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecP224K1Curve();
    }

    public boolean supportsCoordinateSystem(int coord)
    {
        switch (coord)
        {
        case COORD_JACOBIAN:
            return true;
        default:
            return false;
        }
    }

    public BigInteger getQ()
    {
        return q;
    }

    public int getFieldSize()
    {
        return q.bitLength();
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new SecP224K1FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecP224K1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecP224K1Point(this, x, y, zs, withCompression);
    }

    protected ECPoint decompressPoint(int yTilde, BigInteger X1)
    {
        ECFieldElement x = fromBigInteger(X1);
        ECFieldElement alpha = x.square().multiply(x).add(getB());
        ECFieldElement beta = alpha.sqrt();

        //
        // if we can't find a sqrt we haven't got a point on the
        // curve - run!
        //
        if (beta == null)
        {
            throw new RuntimeException("Invalid point compression");
        }

        if (beta.testBitZero() != (yTilde == 1))
        {
            // Use the other root
            beta = beta.negate();
        }

        return new SecP224K1Point(this, x, beta, true);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }
}
