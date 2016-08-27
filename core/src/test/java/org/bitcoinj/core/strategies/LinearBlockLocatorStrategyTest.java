package org.bitcoinj.core.strategies;

import org.junit.Before;
import org.junit.Test;

public class LinearBlockLocatorStrategyTest {

    LinearBlockLocatorStrategy linearBlockLocatorStrategy;

    @Before
    public void setUp() throws Exception {
        linearBlockLocatorStrategy = new LinearBlockLocatorStrategy();

    }

    @Test(expected = NullPointerException.class)
    public void testNullParams() {
        linearBlockLocatorStrategy.setNetworkParameters(null);
    }
}