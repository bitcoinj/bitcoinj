package org.bitcoinj.crypto;

import org.junit.Ignore;
import org.junit.Test;

import java.security.spec.ECPoint;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Tests for LazyECPoint
 */
public class LazyECPointTest {
    org.bouncycastle.math.ec.ECPoint BOUNCY_INFINITY = ECKey.CURVE.getCurve().getInfinity();
    ECPoint JAVA_INFINITY = ECPoint.POINT_INFINITY;

    @Test
    public void convertRandomPoint() {
        LazyECPoint p1 = ECKey.random().pub;
        LazyECPoint p2 = new LazyECPoint(p1.getW());  // Round-trip conversion Bouncy -> JCA -> Bouncy
        assertNotNull(p2);
        assertEquals(p1, p2);
    }

    @Test
    public void infinityConversionTest() {
        LazyECPoint infinity = new LazyECPoint(BOUNCY_INFINITY, true);
        assertEquals(JAVA_INFINITY, infinity.getW());
    }
}
