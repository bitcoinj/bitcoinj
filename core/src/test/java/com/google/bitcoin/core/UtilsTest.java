/**
 * Copyright 2011 Thilo Planz
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.bitcoin.core;

import org.junit.Assert;
import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import static com.google.bitcoin.core.Utils.*;
import static org.junit.Assert.*;

public class UtilsTest {
	
	@Test
	public void testGetDigestThreadSafety() throws InterruptedException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException {
		int concurrency = 1000;
		
		final Method getDigest = Utils.class.getDeclaredMethod("getDigest");
		getDigest.setAccessible(true);
		
		// setup test case
		final byte[] input = new byte[]{
				0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,
				0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,
				0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,
				0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,
				0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,
				0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,
				0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,
				0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,
				0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,
				0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,
				0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,
				0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,};
		MessageDigest digest = (MessageDigest) getDigest.invoke(null);
		digest.update(input);
		final byte[] hash = digest.digest();
		
		final Collection<byte[]> hashes = new ConcurrentLinkedQueue<byte[]>();
		
		List<Thread> threads = new ArrayList<Thread>();
		
		// initialize threads
		for (int i = 0; i < concurrency; i++) {
			Runnable test = new Runnable() {
				
				@Override
				public void run() {
					try {
						MessageDigest digest = (MessageDigest) getDigest.invoke(null);
						digest.update(input);
						hashes.add(digest.digest());
						
					} catch (IllegalAccessException e) {
						throw new RuntimeException(e);
					} catch (IllegalArgumentException e) {
						throw new RuntimeException(e);
					} catch (InvocationTargetException e) {
						throw new RuntimeException(e);
					}
				}
				
			};
			threads.add(new Thread(test));
			
		}
		
		// start parallel tests
		for (Thread thread : threads) {
			thread.start();
			
		}
		
		// let threads finish
		for (Thread thread: threads) {
			thread.join();
			
		}
		
		// compare hashes
		for (byte[] concurrentHash : hashes) {
			assertArrayEquals(hash, concurrentHash);
			
		}
	}

    @Test
    public void testToNanoCoins() {
        // String version
        assertEquals(CENT, toNanoCoins("0.01"));
        assertEquals(CENT, toNanoCoins("1E-2"));
        assertEquals(COIN.add(Utils.CENT), toNanoCoins("1.01"));
        try {
            toNanoCoins("2E-20");
            org.junit.Assert.fail("should not have accepted fractional nanocoins");
        } catch (ArithmeticException e) {
        }

        // int version
        assertEquals(CENT, toNanoCoins(0, 1));

        try {
            toNanoCoins(1, -1);
            fail();
        } catch (IllegalArgumentException e) {}
        try {
            toNanoCoins(-1, 0);
            fail();
        } catch (IllegalArgumentException e) {}
        try {
            toNanoCoins("-1");
            fail();
        } catch (ArithmeticException e) {}
    }

    @Test
    public void testFormatting() {
        assertEquals("1.00", bitcoinValueToFriendlyString(toNanoCoins(1, 0)));
        assertEquals("1.23", bitcoinValueToFriendlyString(toNanoCoins(1, 23)));
        assertEquals("0.001", bitcoinValueToFriendlyString(BigInteger.valueOf(COIN.longValue() / 1000)));
        assertEquals("-1.23", bitcoinValueToFriendlyString(toNanoCoins(1, 23).negate()));
    }
    
    /**
     * Test the bitcoinValueToPlainString amount formatter
     */
    @Test
    public void testBitcoinValueToPlainString() {
        // null argument check
        try {
            bitcoinValueToPlainString(null);
            org.junit.Assert.fail("Expecting IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("Value cannot be null"));
        }

        assertEquals("0.0015", bitcoinValueToPlainString(BigInteger.valueOf(150000)));
        assertEquals("1.23", bitcoinValueToPlainString(toNanoCoins("1.23")));

        assertEquals("0.1", bitcoinValueToPlainString(toNanoCoins("0.1")));
        assertEquals("1.1", bitcoinValueToPlainString(toNanoCoins("1.1")));
        assertEquals("21.12", bitcoinValueToPlainString(toNanoCoins("21.12")));
        assertEquals("321.123", bitcoinValueToPlainString(toNanoCoins("321.123")));
        assertEquals("4321.1234", bitcoinValueToPlainString(toNanoCoins("4321.1234")));
        assertEquals("54321.12345", bitcoinValueToPlainString(toNanoCoins("54321.12345")));
        assertEquals("654321.123456", bitcoinValueToPlainString(toNanoCoins("654321.123456")));
        assertEquals("7654321.1234567", bitcoinValueToPlainString(toNanoCoins("7654321.1234567")));
        try {
            assertEquals("87654321.12345678", bitcoinValueToPlainString(toNanoCoins("87654321.12345678")));
            Assert.fail();  // More than MAX_MONEY
        } catch (Exception e) {}

        // check there are no trailing zeros
        assertEquals("1", bitcoinValueToPlainString(toNanoCoins("1.0")));
        assertEquals("2", bitcoinValueToPlainString(toNanoCoins("2.00")));
        assertEquals("3", bitcoinValueToPlainString(toNanoCoins("3.000")));
        assertEquals("4", bitcoinValueToPlainString(toNanoCoins("4.0000")));
        assertEquals("5", bitcoinValueToPlainString(toNanoCoins("5.00000")));
        assertEquals("6", bitcoinValueToPlainString(toNanoCoins("6.000000")));
        assertEquals("7", bitcoinValueToPlainString(toNanoCoins("7.0000000")));
        assertEquals("8", bitcoinValueToPlainString(toNanoCoins("8.00000000")));
    }    
    
    @Test
    public void testReverseBytes() {
        Assert.assertArrayEquals(new byte[] {1,2,3,4,5}, Utils.reverseBytes(new byte[] {5,4,3,2,1}));
    }

    @Test
    public void testReverseDwordBytes() {
        Assert.assertArrayEquals(new byte[] {1,2,3,4,5,6,7,8}, Utils.reverseDwordBytes(new byte[] {4,3,2,1,8,7,6,5}, -1));
        Assert.assertArrayEquals(new byte[] {1,2,3,4}, Utils.reverseDwordBytes(new byte[] {4,3,2,1,8,7,6,5}, 4));
        Assert.assertArrayEquals(new byte[0], Utils.reverseDwordBytes(new byte[] {4,3,2,1,8,7,6,5}, 0));
        Assert.assertArrayEquals(new byte[0], Utils.reverseDwordBytes(new byte[0], 0));
    }
}
