package org.bouncycastle.math.ec.endo;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPointMap;
import org.bouncycastle.math.ec.ScaleXPointMap;

public class GLVTypeBEndomorphism implements GLVEndomorphism
{
    protected final ECCurve curve;
    protected final GLVTypeBParameters parameters;
    protected final ECPointMap pointMap;

    public GLVTypeBEndomorphism(ECCurve curve, GLVTypeBParameters parameters)
    {
        this.curve = curve;
        this.parameters = parameters;
        this.pointMap = new ScaleXPointMap(curve.fromBigInteger(parameters.getBeta()));
    }

    public BigInteger[] decomposeScalar(BigInteger k)
    {
        int bits = parameters.getBits();
        BigInteger b1 = calculateB(k, parameters.getG1(), bits);
        BigInteger b2 = calculateB(k, parameters.getG2(), bits);

        BigInteger[] v1 = parameters.getV1(), v2 = parameters.getV2();
        BigInteger a = k.subtract((b1.multiply(v1[0])).add(b2.multiply(v2[0])));
        BigInteger b = (b1.multiply(v1[1])).add(b2.multiply(v2[1])).negate();

        return new BigInteger[]{ a, b };
    }

    public ECPointMap getPointMap()
    {
        return pointMap;
    }

    public boolean hasEfficientPointMap()
    {
        return true;
    }

    protected BigInteger calculateB(BigInteger k, BigInteger g, int t)
    {
        boolean negative = (g.signum() < 0);
        BigInteger b = k.multiply(g.abs());
        boolean extra = b.testBit(t - 1);
        b = b.shiftRight(t);
        if (extra)
        {
            b = b.add(ECConstants.ONE);
        }
        return negative ? b.negate() : b;
    }
}
