package org.bouncycastle.math.ec;

import java.math.BigInteger;

import org.bouncycastle.math.ec.endo.GLVEndomorphism;

public class GLVMultiplier extends AbstractECMultiplier
{
    protected final ECCurve curve;
    protected final GLVEndomorphism glvEndomorphism;

    public GLVMultiplier(ECCurve curve, GLVEndomorphism glvEndomorphism)
    {
        if (curve == null || curve.getOrder() == null)
        {
            throw new IllegalArgumentException("Need curve with known group order");
        }

        this.curve = curve;
        this.glvEndomorphism = glvEndomorphism;
    }

    protected ECPoint multiplyPositive(ECPoint p, BigInteger k)
    {
        if (!curve.equals(p.getCurve()))
        {
            throw new IllegalStateException();
        }

        BigInteger n = p.getCurve().getOrder();
        BigInteger[] ab = glvEndomorphism.decomposeScalar(k.mod(n));
        BigInteger a = ab[0], b = ab[1];

        ECPointMap pointMap = glvEndomorphism.getPointMap();
        if (glvEndomorphism.hasEfficientPointMap())
        {
            return ECAlgorithms.implShamirsTrickWNaf(p, a, pointMap, b);
        }

        return ECAlgorithms.implShamirsTrickWNaf(p, a, pointMap.map(p), b);
    }
}
