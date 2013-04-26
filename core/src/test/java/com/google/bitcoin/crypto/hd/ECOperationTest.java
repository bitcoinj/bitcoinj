package com.google.bitcoin.crypto.hd;

import junit.framework.Assert;
import org.junit.Test;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Random;

/**
 * @author Matija Mazi <br/>
 * This is just to see if I know how to use the EC machinery.
 */
public class ECOperationTest {

    private static final ECDomainParameters EC_PARAMS = HDUtils.getEcParams();
    private static final ECCurve.Fp CURVE = (ECCurve.Fp) EC_PARAMS.getCurve();
    private static final BigInteger N = EC_PARAMS.getN();
    private static final Random RND = new Random();

    @Test
    public void testFieldElementToBigIntConversions() throws Exception {
        for (int i = 0; i < 1000; i++) {
            BigInteger bi = rnd();
            Assert.assertEquals("Case " + i, bi, CURVE.fromBigInteger(bi).toBigInteger());
        }
    }

    /**
     * Test that a * b = b * a, where a, b are scalars.
     */
    @Test
    public void testCommutativity() throws Exception {
        for (int i = 0; i < 1000; i++) {
            BigInteger biA = rnd();
            BigInteger biB = rnd();
            ECFieldElement scA = CURVE.fromBigInteger(biA);
            ECFieldElement scB = CURVE.fromBigInteger(biB);
            Assert.assertEquals("Scalar Commutativity " + i, scB.multiply(scA).toBigInteger(), scA.multiply(scB).toBigInteger());
        }
    }

    /**
     * Test that (ab)P = a*(b*P), where a, b are scalars and P is an EC point.
     */
    @Test
    public void testAssociativity() throws Exception {
        for (int i = 0; i < 30; i++) {
            BigInteger biA = rnd();
            BigInteger biB = rnd();
            ECPoint point = getRandomPoint();
            Assert.assertEquals("Associativity " + i, point.multiply(biB).multiply(biA), point.multiply(biA.multiply(biB).mod(N)));
        }
    }

    private ECPoint getRandomPoint() {
        return EC_PARAMS.getG().multiply(rnd());
    }

    private BigInteger rnd() {
        BigInteger r;
        do r = new BigInteger(N.bitLength(), RND); while (r.compareTo(N) >= 0);
        return r;
    }
}
