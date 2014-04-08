package org.bouncycastle.math.ec;

/**
 * Class holding precomputation data for the WTNAF (Window
 * <code>&tau;</code>-adic Non-Adjacent Form) algorithm.
 */
public class WTauNafPreCompInfo implements PreCompInfo
{
    /**
     * Array holding the precomputed <code>ECPoint.F2m</code>s used for the
     * WTNAF multiplication in <code>
     * {@link org.bouncycastle.math.ec.multiplier.WTauNafMultiplier.multiply()
     * WTauNafMultiplier.multiply()}</code>.
     */
    protected ECPoint.F2m[] preComp = null;

    public ECPoint.F2m[] getPreComp()
    {
        return preComp;
    }

    public void setPreComp(ECPoint.F2m[] preComp)
    {
        this.preComp = preComp;
    }
}
