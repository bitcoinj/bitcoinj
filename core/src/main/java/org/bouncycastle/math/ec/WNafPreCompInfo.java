package org.bouncycastle.math.ec;

/**
 * Class holding precomputation data for the WNAF (Window Non-Adjacent Form)
 * algorithm.
 */
public class WNafPreCompInfo implements PreCompInfo
{
    /**
     * Array holding the precomputed <code>ECPoint</code>s used for a Window
     * NAF multiplication.
     */
    protected ECPoint[] preComp = null;

    /**
     * Array holding the negations of the precomputed <code>ECPoint</code>s used
     * for a Window NAF multiplication.
     */
    protected ECPoint[] preCompNeg = null;

    /**
     * Holds an <code>ECPoint</code> representing twice(this). Used for the
     * Window NAF multiplication to create or extend the precomputed values.
     */
    protected ECPoint twice = null;

    public ECPoint[] getPreComp()
    {
        return preComp;
    }

    public void setPreComp(ECPoint[] preComp)
    {
        this.preComp = preComp;
    }

    public ECPoint[] getPreCompNeg()
    {
        return preCompNeg;
    }

    public void setPreCompNeg(ECPoint[] preCompNeg)
    {
        this.preCompNeg = preCompNeg;
    }

    public ECPoint getTwice()
    {
        return twice;
    }

    public void setTwice(ECPoint twice)
    {
        this.twice = twice;
    }
}
