package org.bouncycastle.crypto.agreement.jpake;

import java.math.BigInteger;

/**
 * A pre-computed prime order group for use during a J-PAKE exchange.
 * <p>
 * Typically a Schnorr group is used.  In general, J-PAKE can use any prime order group
 * that is suitable for public key cryptography, including elliptic curve cryptography.
 * <p>
 * See {@link JPAKEPrimeOrderGroups} for convenient standard groups.
 * <p>
 * NIST <a href="http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/DSA2_All.pdf">publishes</a>
 * many groups that can be used for the desired level of security.
 */
public class JPAKEPrimeOrderGroup
{
    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger g;

    /**
     * Constructs a new {@link JPAKEPrimeOrderGroup}.
     * <p>
     * In general, you should use one of the pre-approved groups from
     * {@link JPAKEPrimeOrderGroups}, rather than manually constructing one.
     * <p>
     * The following basic checks are performed:
     * <ul>
     * <li>p-1 must be evenly divisible by q</li>
     * <li>g must be in [2, p-1]</li>
     * <li>g^q mod p must equal 1</li>
     * <li>p must be prime (within reasonably certainty)</li>
     * <li>q must be prime (within reasonably certainty)</li>
     * </ul>
     * <p>
     * The prime checks are performed using {@link BigInteger#isProbablePrime(int)},
     * and are therefore subject to the same probability guarantees.
     * <p>
     * These checks prevent trivial mistakes.
     * However, due to the small uncertainties if p and q are not prime,
     * advanced attacks are not prevented.
     * Use it at your own risk.
     *
     * @throws NullPointerException if any argument is null
     * @throws IllegalArgumentException if any of the above validations fail
     */
    public JPAKEPrimeOrderGroup(BigInteger p, BigInteger q, BigInteger g)
    {
        /*
         * Don't skip the checks on user-specified groups.
         */
        this(p, q, g, false);
    }

    /**
     * Internal package-private constructor used by the pre-approved
     * groups in {@link JPAKEPrimeOrderGroups}.
     * These pre-approved groups can avoid the expensive checks.
     */
    JPAKEPrimeOrderGroup(BigInteger p, BigInteger q, BigInteger g, boolean skipChecks)
    {
        JPAKEUtil.validateNotNull(p, "p");
        JPAKEUtil.validateNotNull(q, "q");
        JPAKEUtil.validateNotNull(g, "g");

        if (!skipChecks)
        {
            if (!p.subtract(JPAKEUtil.ONE).mod(q).equals(JPAKEUtil.ZERO))
            {
                throw new IllegalArgumentException("p-1 must be evenly divisible by q");
            }
            if (g.compareTo(BigInteger.valueOf(2)) == -1 || g.compareTo(p.subtract(JPAKEUtil.ONE)) == 1)
            {
                throw new IllegalArgumentException("g must be in [2, p-1]");
            }
            if (!g.modPow(q, p).equals(JPAKEUtil.ONE))
            {
                throw new IllegalArgumentException("g^q mod p must equal 1");
            }
            /*
             * Note that these checks do not guarantee that p and q are prime.
             * We just have reasonable certainty that they are prime.
             */
            if (!p.isProbablePrime(20))
            {
                throw new IllegalArgumentException("p must be prime");
            }
            if (!q.isProbablePrime(20))
            {
                throw new IllegalArgumentException("q must be prime");
            }
        }

        this.p = p;
        this.q = q;
        this.g = g;
    }

    public BigInteger getP()
    {
        return p;
    }

    public BigInteger getQ()
    {
        return q;
    }

    public BigInteger getG()
    {
        return g;
    }

}
