package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.field.FiniteFields;
import org.bouncycastle.util.encoders.Hex;

public class SecP384R1Curve extends ECCurve
{
    public static final BigInteger q = new BigInteger(1,
        Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF"));

    private static final int SecP384R1_DEFAULT_COORDS = COORD_JACOBIAN;

    protected SecP384R1Point infinity;

    public SecP384R1Curve()
    {
        super(FiniteFields.getPrimeField(q));

        this.infinity = new SecP384R1Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1,
            Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC")));
        this.b = fromBigInteger(new BigInteger(1,
            Hex.decode("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF")));
        this.order = new BigInteger(1, Hex.decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"));
        this.cofactor = BigInteger.valueOf(1);

        this.coord = SecP384R1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecP384R1Curve();
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
        return new SecP384R1FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecP384R1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecP384R1Point(this, x, y, zs, withCompression);
    }

    protected ECPoint decompressPoint(int yTilde, BigInteger X1)
    {
        ECFieldElement x = fromBigInteger(X1);
        ECFieldElement alpha = x.square().add(getA()).multiply(x).add(getB());
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

        return new SecP384R1Point(this, x, beta, true);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }
}
