package org.bouncycastle.math.ec;

import java.math.BigInteger;

/**
 * Class implementing the WTNAF (Window
 * <code>&tau;</code>-adic Non-Adjacent Form) algorithm.
 */
public class WTauNafMultiplier extends AbstractECMultiplier
{
    // TODO Create WTauNafUtil class and move various functionality into it
    static final String PRECOMP_NAME = "bc_wtnaf";

    /**
     * Multiplies a {@link org.bouncycastle.math.ec.ECPoint.F2m ECPoint.F2m}
     * by <code>k</code> using the reduced <code>&tau;</code>-adic NAF (RTNAF)
     * method.
     * @param p The ECPoint.F2m to multiply.
     * @param k The integer by which to multiply <code>k</code>.
     * @return <code>p</code> multiplied by <code>k</code>.
     */
    protected ECPoint multiplyPositive(ECPoint point, BigInteger k)
    {
        if (!(point instanceof ECPoint.F2m))
        {
            throw new IllegalArgumentException("Only ECPoint.F2m can be " +
                    "used in WTauNafMultiplier");
        }

        ECPoint.F2m p = (ECPoint.F2m)point;
        ECCurve.F2m curve = (ECCurve.F2m)p.getCurve();
        int m = curve.getM();
        byte a = curve.getA().toBigInteger().byteValue();
        byte mu = curve.getMu();
        BigInteger[] s = curve.getSi();

        ZTauElement rho = Tnaf.partModReduction(k, m, a, s, mu, (byte)10);

        return multiplyWTnaf(p, rho, curve.getPreCompInfo(p, PRECOMP_NAME), a, mu);
    }

    /**
     * Multiplies a {@link org.bouncycastle.math.ec.ECPoint.F2m ECPoint.F2m}
     * by an element <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code> using
     * the <code>&tau;</code>-adic NAF (TNAF) method.
     * @param p The ECPoint.F2m to multiply.
     * @param lambda The element <code>&lambda;</code> of
     * <code><b>Z</b>[&tau;]</code> of which to compute the
     * <code>[&tau;]</code>-adic NAF.
     * @return <code>p</code> multiplied by <code>&lambda;</code>.
     */
    private ECPoint.F2m multiplyWTnaf(ECPoint.F2m p, ZTauElement lambda,
            PreCompInfo preCompInfo, byte a, byte mu)
    {
        ZTauElement[] alpha = (a == 0) ? Tnaf.alpha0 : Tnaf.alpha1;

        BigInteger tw = Tnaf.getTw(mu, Tnaf.WIDTH);

        byte[]u = Tnaf.tauAdicWNaf(mu, lambda, Tnaf.WIDTH,
            BigInteger.valueOf(Tnaf.POW_2_WIDTH), tw, alpha);

        return multiplyFromWTnaf(p, u, preCompInfo);
    }

    /**
     * Multiplies a {@link org.bouncycastle.math.ec.ECPoint.F2m ECPoint.F2m}
     * by an element <code>&lambda;</code> of <code><b>Z</b>[&tau;]</code>
     * using the window <code>&tau;</code>-adic NAF (TNAF) method, given the
     * WTNAF of <code>&lambda;</code>.
     * @param p The ECPoint.F2m to multiply.
     * @param u The the WTNAF of <code>&lambda;</code>..
     * @return <code>&lambda; * p</code>
     */
    private static ECPoint.F2m multiplyFromWTnaf(ECPoint.F2m p, byte[] u, PreCompInfo preCompInfo)
    {
        ECCurve.F2m curve = (ECCurve.F2m)p.getCurve();
        byte a = curve.getA().toBigInteger().byteValue();

        ECPoint.F2m[] pu;
        if ((preCompInfo == null) || !(preCompInfo instanceof WTauNafPreCompInfo))
        {
            pu = Tnaf.getPreComp(p, a);

            WTauNafPreCompInfo pre = new WTauNafPreCompInfo();
            pre.setPreComp(pu);
            curve.setPreCompInfo(p, PRECOMP_NAME, pre);
        }
        else
        {
            pu = ((WTauNafPreCompInfo)preCompInfo).getPreComp();
        }

        // q = infinity
        ECPoint.F2m q = (ECPoint.F2m) p.getCurve().getInfinity();
        for (int i = u.length - 1; i >= 0; i--)
        {
            q = Tnaf.tau(q);
            byte ui = u[i];
            if (ui != 0)
            {
                if (ui > 0)
                {
                    q = q.addSimple(pu[ui]);
                }
                else
                {
                    q = q.subtractSimple(pu[-ui]);
                }
            }
        }

        return q;
    }
}
