package com.subgraph.orchid.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import com.subgraph.orchid.TorException;

public class TorRandom {

	private final SecureRandom random;
	
	public TorRandom() {
		random = createRandom();
	}
	
	private static SecureRandom createRandom() {
		try {
			return SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			throw new TorException(e);
		}
	}

	public byte[] getBytes(int n) {
		final byte[] bs = new byte[n];
		random.nextBytes(bs);
		return bs;
	}

	public long nextLong(long n) {
		long bits, val;
		do {
			bits = nextLong();
			val = bits % n;
		} while(bits - val + (n - 1) < 0);
		return val;
	}

	public int nextInt(int n) {
		return random.nextInt(n);
	}
	
	public int nextInt() {
		return random.nextInt() & Integer.MAX_VALUE;
	}
	
	/**
	 * Return a uniformly distributed positive random value between 0 and Long.MAX_VALUE
	 * 
	 * @return A positive random value between 0 and Long.MAX_VALUE.
	 */
	public long nextLong() {
		return random.nextLong() & Long.MAX_VALUE;
	}

}
