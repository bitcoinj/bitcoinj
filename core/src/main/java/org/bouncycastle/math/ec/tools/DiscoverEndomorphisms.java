package org.bouncycastle.math.ec.tools;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

public class DiscoverEndomorphisms
{
    private static final int radix = 16;

    public static void main(String[] args)
    {
        if (args.length < 1)
        {
            System.err.println("Expected a list of curve names as arguments");
            return;
        }

        for (int i = 0; i < args.length; ++i)
        {
            discoverEndomorphism(args[i]);
        }
    }

    private static void discoverEndomorphism(String curveName)
    {
        X9ECParameters x9 = ECNamedCurveTable.getByName(curveName);
        if (x9 == null)
        {
            System.err.println("Unknown curve: " + curveName);
            return;
        }

        ECCurve c = x9.getCurve();
        if (ECAlgorithms.isFpCurve(c))
        {
            BigInteger characteristic = c.getField().getCharacteristic();

            if (c.getA().isZero() && characteristic.mod(ECConstants.THREE).equals(ECConstants.ONE))
            {
                System.out.println("Curve '" + curveName + "' has a 'GLV Type B' endomorphism with these parameters: ");
                printGLVTypeBParameters(x9);
            }
        }
    }

    private static void printGLVTypeBParameters(X9ECParameters x9)
    {
        BigInteger n = x9.getN();
        BigInteger[] v1 = null;
        BigInteger[] v2 = null;

        // x^2 + x + 1 = 0 mod n
        BigInteger lambda = solveQuadraticEquation(n, ECConstants.ONE, ECConstants.ONE);

        BigInteger[] rt = extEuclidGLV(n, lambda);
        v1 = new BigInteger[]{ rt[2], rt[3].negate() };
        v2 = chooseShortest(new BigInteger[]{ rt[0], rt[1].negate() }, new BigInteger[]{ rt[4], rt[5].negate() });

        /*
         * If elements of v2 are not bounded by sqrt(n), then if r1/t1 are relatively prime there
         * _may_ yet be a GLV generator, so search for it. See
         * "Integer Decomposition for Fast Scalar Multiplication on Elliptic Curves", D. Kim, S. Lim
         * (SAC 2002)
         */
        if (!isVectorBoundedBySqrt(v2, n) && areRelativelyPrime(v1[0], v1[1]))
        {
            BigInteger r = v1[0], t = v1[1], s = r.add(t.multiply(lambda)).divide(n);

            BigInteger[] vw = extEuclidBezout(new BigInteger[]{ s.abs(), t.abs() });
            BigInteger v = vw[0], w = vw[1];

            if (s.signum() < 0)
            {
                v = v.negate();
            }
            if (t.signum() > 0)
            {
                w = w.negate();
            }

            BigInteger check = s.multiply(v).subtract(t.multiply(w));
            if (!check.equals(ECConstants.ONE))
            {
                throw new IllegalStateException();
            }

            BigInteger x = w.multiply(n).subtract(v.multiply(lambda));

            BigInteger base1 = v.negate();
            BigInteger base2 = x.negate();

            /*
             * We calculate the range(s) conservatively large to avoid messy rounding issues, so
             * there may be spurious candidate generators, but we won't miss any.
             */
            BigInteger sqrtN = isqrt(n.subtract(ECConstants.ONE)).add(ECConstants.ONE);

            BigInteger[] I1 = calculateRange(base1, sqrtN, t);
            BigInteger[] I2 = calculateRange(base2, sqrtN, r);

            BigInteger[] range = intersect(I1, I2);
            if (range != null)
            {
                for (BigInteger alpha = range[0]; alpha.compareTo(range[1]) <= 0; alpha = alpha.add(ECConstants.ONE))
                {
                    BigInteger[] candidate = new BigInteger[]{ x.add(alpha.multiply(r)), v.add(alpha.multiply(t)) };
                    if (isShorter(candidate, v2))
                    {
                        v2 = candidate;
                    }
                }
            }
        }

        /*
         * 'Beta' is a field element of order 3. There are only two such values besides 1; determine which of them
         * corresponds to our choice for 'Lambda'.
         */
        ECFieldElement beta;
        {
            ECPoint G = x9.getG().normalize();
            ECPoint mapG = G.multiply(lambda).normalize();
            if (!G.getYCoord().equals(mapG.getYCoord()))
            {
                throw new IllegalStateException("Derivation of GLV Type B parameters failed unexpectedly");
            }
    
            BigInteger q = x9.getCurve().getField().getCharacteristic();
            BigInteger e = q.divide(ECConstants.THREE);

            SecureRandom random = new SecureRandom();
            BigInteger b;
            do
            {
                BigInteger r = BigIntegers.createRandomInRange(ECConstants.TWO, q.subtract(ECConstants.TWO), random);
                b = r.modPow(e, q);
            }
            while (b.equals(ECConstants.ONE));

            beta = x9.getCurve().fromBigInteger(ECConstants.TWO.modPow(e, q));

            if (!G.getXCoord().multiply(beta).equals(mapG.getXCoord()))
            {
                beta = beta.square();
                if (!G.getXCoord().multiply(beta).equals(mapG.getXCoord()))
                {
                    throw new IllegalStateException("Derivation of GLV Type B parameters failed unexpectedly");
                }
            }
        }

        /*
         * These parameters are used to avoid division when decomposing the scalar in a GLV point multiplication
         */
        BigInteger d = (v1[0].multiply(v2[1])).subtract(v1[1].multiply(v2[0]));

        int bits = n.bitLength() + 2;
        BigInteger g1 = roundQuotient(v2[1].shiftLeft(bits), d);
        BigInteger g2 = roundQuotient(v1[1].shiftLeft(bits), d).negate();

        printProperty("Beta", beta.toBigInteger().toString(radix));
        printProperty("Lambda", lambda.toString(radix));
        printProperty("v1", "{ " + v1[0].toString(radix) + ", " + v1[1].toString(radix) + " }");
        printProperty("v2", "{ " + v2[0].toString(radix) + ", " + v2[1].toString(radix) + " }");
        printProperty("(OPT) g1", g1.toString(radix));
        printProperty("(OPT) g2", g2.toString(radix));
        printProperty("(OPT) bits", bits);
    }

    private static void printProperty(String name, Object value)
    {
        StringBuffer sb = new StringBuffer("  ");
        sb.append(name);
        while (sb.length() < 20)
        {
            sb.append(' ');
        }
        sb.append("= ");
        sb.append(value.toString());
        System.out.println(sb.toString());
    }

    private static boolean areRelativelyPrime(BigInteger a, BigInteger b)
    {
        return a.gcd(b).equals(ECConstants.ONE);
    }

    private static BigInteger[] calculateRange(BigInteger mid, BigInteger off, BigInteger div)
    {
        BigInteger i1 = mid.subtract(off).divide(div);
        BigInteger i2 = mid.add(off).divide(div);
        return order(i1, i2);
    }

    private static BigInteger[] extEuclidBezout(BigInteger[] ab)
    {
        boolean swap = ab[0].compareTo(ab[1]) < 0;
        if (swap)
        {
            swap(ab);
        }

        BigInteger r0 = ab[0], r1 = ab[1];
        BigInteger s0 = ECConstants.ONE, s1 = ECConstants.ZERO;
        BigInteger t0 = ECConstants.ZERO, t1 = ECConstants.ONE;

        while (r1.compareTo(BigInteger.ONE) > 0)
        {
            BigInteger[] qr = r0.divideAndRemainder(r1);
            BigInteger q = qr[0], r2 = qr[1];

            BigInteger s2 = s0.subtract(q.multiply(s1));
            BigInteger t2 = t0.subtract(q.multiply(t1));

            r0 = r1;
            r1 = r2;
            s0 = s1;
            s1 = s2;
            t0 = t1;
            t1 = t2;
        }

        if (r1.signum() <= 0)
        {
            throw new IllegalStateException();
        }

        BigInteger[] st = new BigInteger[]{ s1, t1 };
        if (swap)
        {
            swap(st);
        }
        return st;
    }

    private static BigInteger[] extEuclidGLV(BigInteger n, BigInteger lambda)
    {
        BigInteger r0 = n, r1 = lambda;
        // BigInteger s0 = ECConstants.ONE, s1 = ECConstants.ZERO;
        BigInteger t0 = ECConstants.ZERO, t1 = ECConstants.ONE;

        for (;;)
        {
            BigInteger[] qr = r0.divideAndRemainder(r1);
            BigInteger q = qr[0], r2 = qr[1];

            // BigInteger s2 = s0.subtract(q.multiply(s1));
            BigInteger t2 = t0.subtract(q.multiply(t1));

            if (isLessThanSqrt(r1, n))
            {
                return new BigInteger[]{ r0, t0, r1, t1, r2, t2 };
            }

            r0 = r1;
            r1 = r2;
            // s0 = s1;
            // s1 = s2;
            t0 = t1;
            t1 = t2;
        }
    }

    private static BigInteger[] chooseShortest(BigInteger[] u, BigInteger[] v)
    {
        return isShorter(u, v) ? u : v;
    }

    private static BigInteger[] intersect(BigInteger[] ab, BigInteger[] cd)
    {
        BigInteger min = ab[0].max(cd[0]);
        BigInteger max = ab[1].min(cd[1]);
        if (min.compareTo(max) > 0)
        {
            return null;
        }
        return new BigInteger[]{ min, max };
    }

    private static boolean isLessThanSqrt(BigInteger a, BigInteger b)
    {
        a = a.abs();
        b = b.abs();
        int target = b.bitLength(), maxBits = a.bitLength() * 2, minBits = maxBits - 1;
        return minBits <= target && (maxBits < target || a.multiply(a).compareTo(b) < 0);
    }

    private static boolean isShorter(BigInteger[] u, BigInteger[] v)
    {
        BigInteger u1 = u[0].abs(), u2 = u[1].abs(), v1 = v[0].abs(), v2 = v[1].abs();

        // TODO Check whether "shorter" just means by rectangle norm:
        // return u1.max(u2).compareTo(v1.max(v2)) < 0;

        boolean c1 = u1.compareTo(v1) < 0, c2 = u2.compareTo(v2) < 0;
        if (c1 == c2)
        {
            return c1;
        }

        BigInteger du = u1.multiply(u1).add(u2.multiply(u2));
        BigInteger dv = v1.multiply(v1).add(v2.multiply(v2));

        return du.compareTo(dv) < 0;
    }

    private static boolean isVectorBoundedBySqrt(BigInteger[] v, BigInteger n)
    {
        BigInteger max = v[0].abs().max(v[1].abs());
        return isLessThanSqrt(max, n);
    }

    private static BigInteger[] order(BigInteger a, BigInteger b)
    {
        if (a.compareTo(b) <= 0)
        {
            return new BigInteger[]{ a, b };
        }
        return new BigInteger[]{ b, a };
    }

    private static BigInteger roundQuotient(BigInteger x, BigInteger y)
    {
        boolean negative = (x.signum() != y.signum());
        x = x.abs();
        y = y.abs();
        BigInteger result = x.add(y.shiftRight(1)).divide(y);
        return negative ? result.negate() : result;
    }

    private static BigInteger solveQuadraticEquation(BigInteger n, BigInteger r, BigInteger s)
    {
        BigInteger det = r.multiply(r).subtract(s.shiftLeft(2)).mod(n);

        BigInteger root = new ECFieldElement.Fp(n, det).sqrt().toBigInteger();
        if (!root.testBit(0))
        {
            root = n.subtract(root);
        }

        return root.shiftRight(1); // NOTE: implicit -1 of the low-bit
    }

    private static BigInteger isqrt(BigInteger x)
    {
        BigInteger g0 = x.shiftRight(x.bitLength() / 2);
        for (;;)
        {
            BigInteger g1 = g0.add(x.divide(g0)).shiftRight(1);
            if (g1.equals(g0))
            {
                return g1;
            }
            g0 = g1;
        }
    }

    private static void swap(BigInteger[] ab)
    {
        BigInteger tmp = ab[0];
        ab[0] = ab[1];
        ab[1] = tmp;
    }
}
