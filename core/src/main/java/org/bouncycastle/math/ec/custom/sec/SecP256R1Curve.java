package org.bouncycastle.math.ec.custom.sec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.field.FiniteFields;
import org.bouncycastle.util.encoders.Hex;

public class SecP256R1Curve extends ECCurve
{
    public static final BigInteger q = new BigInteger(1,
        Hex.decode("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"));

    private static final int SecP256R1_DEFAULT_COORDS = COORD_JACOBIAN;

    protected SecP256R1Point infinity;

    public SecP256R1Curve()
    {
        super(FiniteFields.getPrimeField(q));

        this.infinity = new SecP256R1Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1,
            Hex.decode("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC")));
        this.b = fromBigInteger(new BigInteger(1,
            Hex.decode("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B")));
        this.order = new BigInteger(1, Hex.decode("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"));
        this.cofactor = BigInteger.valueOf(1);

        this.coord = SecP256R1_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new SecP256R1Curve();
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
        return new SecP256R1FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new SecP256R1Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new SecP256R1Point(this, x, y, zs, withCompression);
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

        return new SecP256R1Point(this, x, beta, true);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }
}
