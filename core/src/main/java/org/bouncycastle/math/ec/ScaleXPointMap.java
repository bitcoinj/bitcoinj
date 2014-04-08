package org.bouncycastle.math.ec;

public class ScaleXPointMap implements ECPointMap
{
    protected final ECFieldElement scale;

    public ScaleXPointMap(ECFieldElement scale)
    {
        this.scale = scale;
    }

    public ECPoint map(ECPoint p)
    {
        return p.scaleX(scale);
    }
}
