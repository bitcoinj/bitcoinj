package org.bouncycastle.math.ec;

/**
 * Class holding precomputation data for fixed-point multiplications.
 */
public class FixedPointPreCompInfo implements PreCompInfo
{
    /**
     * Array holding the precomputed <code>ECPoint</code>s used for a fixed
     * point multiplication.
     */
    protected ECPoint[] preComp = null;

    public ECPoint[] getPreComp()
    {
        return preComp;
    }

    public void setPreComp(ECPoint[] preComp)
    {
        this.preComp = preComp;
    }
}
