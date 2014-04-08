package org.bouncycastle.crypto.prng.drbg;

import org.bouncycastle.math.ec.ECPoint;

/**
 * General class for providing point pairs for use with DualEC DRBG. See NIST SP 800-90A for further details.
 */
public class DualECPoints
{
    private final ECPoint p;
    private final ECPoint q;
    private final int securityStrength;
    private final int cofactor;

    /**
     * Base Constructor.
     * <p>
     * The cofactor is used to calculate the output block length (maxOutlen) according to
     * <pre>
     *     max_outlen = largest multiple of 8 less than ((field size in bits) - (13 + log2(cofactor))
     * </pre>
     *
     * @param securityStrength maximum security strength to be associated with these parameters
     * @param p the P point.
     * @param q the Q point.
     * @param cofactor cofactor associated with the domain parameters for the point generation.
     */
    public DualECPoints(int securityStrength, ECPoint p, ECPoint q, int cofactor)
    {
        if (!p.getCurve().equals(q.getCurve()))
        {
            throw new IllegalArgumentException("points need to be on the same curve");
        }

        this.securityStrength = securityStrength;
        this.p = p;
        this.q = q;
        this.cofactor = cofactor;
    }

    public int getSeedLen()
    {
        return p.getCurve().getFieldSize();
    }

    public int getMaxOutlen()
    {
        return ((p.getCurve().getFieldSize() - (13 + log2(cofactor))) / 8) * 8;
    }

    public ECPoint getP()
    {
        return p;
    }

    public ECPoint getQ()
    {
        return q;
    }

    public int getSecurityStrength()
    {
        return securityStrength;
    }

    public int getCofactor()
    {
        return cofactor;
    }

    private static int log2(int value)
    {
        int log = 0;

        while ((value >>= 1) != 0)
        {
            log++;
        }

        return log;
    }
}
