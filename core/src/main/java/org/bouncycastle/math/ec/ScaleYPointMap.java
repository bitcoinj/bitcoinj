package org.bouncycastle.math.ec;

public class ScaleYPointMap implements ECPointMap
{
    protected final ECFieldElement scale;

    public ScaleYPointMap(ECFieldElement scale)
    {
        this.scale = scale;
    }

    public ECPoint map(ECPoint p)
    {
        return p.scaleY(scale);
    }
}
