// $Id: WhirlpoolCore.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the core operations for the Whirlpool digest
 * algorithm family. The three variants differ only in the tables of
 * constants which are provided to this implementation in the constructor.</p>
 *
 * <pre>
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 * </pre>
 *
 * @version   $Revision: 214 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class WhirlpoolCore extends MDHelper {

	/**
	 * Create the object.
	 */
	WhirlpoolCore(long[] T0, long[] T1, long[] T2, long[] T3,
		long[] T4, long[] T5, long[] T6, long[] T7, long[] RC)
	{
		super(false, 32);
		this.T0 = T0;
		this.T1 = T1;
		this.T2 = T2;
		this.T3 = T3;
		this.T4 = T4;
		this.T5 = T5;
		this.T6 = T6;
		this.T7 = T7;
		this.RC = RC;
	}

	private final long[] T0, T1, T2, T3, T4, T5, T6, T7, RC;

	private long state0, state1, state2, state3;
	private long state4, state5, state6, state7;

	/** @see DigestEngine */
	protected Digest copyState(WhirlpoolCore d)
	{
		d.state0 = state0;
		d.state1 = state1;
		d.state2 = state2;
		d.state3 = state3;
		d.state4 = state4;
		d.state5 = state5;
		d.state6 = state6;
		d.state7 = state7;
		return super.copyState(d);
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 64;
	}

	/** @see Digest */
	public int getBlockLength()
	{
		return 64;
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		state0 = 0;
		state1 = 0;
		state2 = 0;
		state3 = 0;
		state4 = 0;
		state5 = 0;
		state6 = 0;
		state7 = 0;
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		makeMDPadding();
		encodeLELong(state0, output, outputOffset);
		encodeLELong(state1, output, outputOffset + 8);
		encodeLELong(state2, output, outputOffset + 16);
		encodeLELong(state3, output, outputOffset + 24);
		encodeLELong(state4, output, outputOffset + 32);
		encodeLELong(state5, output, outputOffset + 40);
		encodeLELong(state6, output, outputOffset + 48);
		encodeLELong(state7, output, outputOffset + 56);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		engineReset();
	}

	/**
	 * Decode a 64-bit little-endian integer.
	 *
	 * @param buf   the source buffer
	 * @param off   the source offset
	 * @return  the decoded integer
	 */
	private static final long decodeLELong(byte[] buf, int off)
	{
		return (buf[off + 0] & 0xFF)
			| ((long)(buf[off + 1] & 0xFF) << 8)
			| ((long)(buf[off + 2] & 0xFF) << 16)
			| ((long)(buf[off + 3] & 0xFF) << 24)
			| ((long)(buf[off + 4] & 0xFF) << 32)
			| ((long)(buf[off + 5] & 0xFF) << 40)
			| ((long)(buf[off + 6] & 0xFF) << 48)
			| ((long)(buf[off + 7] & 0xFF) << 56);
	}

	/**
	 * Encode a 64-bit integer with little-endian convention.
	 *
	 * @param val   the integer to encode
	 * @param dst   the destination buffer
	 * @param off   the destination offset
	 */
	private static final void encodeLELong(long val, byte[] dst, int off)
	{
		dst[off + 0] = (byte)val;
		dst[off + 1] = (byte)((int)val >>> 8);
		dst[off + 2] = (byte)((int)val >>> 16);
		dst[off + 3] = (byte)((int)val >>> 24);
		dst[off + 4] = (byte)(val >>> 32);
		dst[off + 5] = (byte)(val >>> 40);
		dst[off + 6] = (byte)(val >>> 48);
		dst[off + 7] = (byte)(val >>> 56);
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		long n0 = decodeLELong(data, 0),  sn0 = n0;
		long n1 = decodeLELong(data, 8),  sn1 = n1;
		long n2 = decodeLELong(data, 16), sn2 = n2;
		long n3 = decodeLELong(data, 24), sn3 = n3;
		long n4 = decodeLELong(data, 32), sn4 = n4;
		long n5 = decodeLELong(data, 40), sn5 = n5;
		long n6 = decodeLELong(data, 48), sn6 = n6;
		long n7 = decodeLELong(data, 56), sn7 = n7;
		long h0 = state0, h1 = state1, h2 = state2, h3 = state3;
		long h4 = state4, h5 = state5, h6 = state6, h7 = state7;
		int r;

		n0 ^= h0;
		n1 ^= h1;
		n2 ^= h2;
		n3 ^= h3;
		n4 ^= h4;
		n5 ^= h5;
		n6 ^= h6;
		n7 ^= h7;
		for (r = 0; r < 10; r ++) {
			long t0, t1, t2, t3, t4, t5, t6, t7;

			t0 = T0[(int)h0 & 0xFF]
				^ T1[((int)h7 >> 8) & 0xFF]
				^ T2[((int)h6 >> 16) & 0xFF]
				^ T3[((int)h5 >> 24) & 0xFF]
				^ T4[(int)(h4 >> 32) & 0xFF]
				^ T5[(int)(h3 >> 40) & 0xFF]
				^ T6[(int)(h2 >> 48) & 0xFF]
				^ T7[(int)(h1 >> 56) & 0xFF]
				^ RC[r];
			t1 = T0[(int)h1 & 0xFF]
				^ T1[((int)h0 >> 8) & 0xFF]
				^ T2[((int)h7 >> 16) & 0xFF]
				^ T3[((int)h6 >> 24) & 0xFF]
				^ T4[(int)(h5 >> 32) & 0xFF]
				^ T5[(int)(h4 >> 40) & 0xFF]
				^ T6[(int)(h3 >> 48) & 0xFF]
				^ T7[(int)(h2 >> 56) & 0xFF];
			t2 = T0[(int)h2 & 0xFF]
				^ T1[((int)h1 >> 8) & 0xFF]
				^ T2[((int)h0 >> 16) & 0xFF]
				^ T3[((int)h7 >> 24) & 0xFF]
				^ T4[(int)(h6 >> 32) & 0xFF]
				^ T5[(int)(h5 >> 40) & 0xFF]
				^ T6[(int)(h4 >> 48) & 0xFF]
				^ T7[(int)(h3 >> 56) & 0xFF];
			t3 = T0[(int)h3 & 0xFF]
				^ T1[((int)h2 >> 8) & 0xFF]
				^ T2[((int)h1 >> 16) & 0xFF]
				^ T3[((int)h0 >> 24) & 0xFF]
				^ T4[(int)(h7 >> 32) & 0xFF]
				^ T5[(int)(h6 >> 40) & 0xFF]
				^ T6[(int)(h5 >> 48) & 0xFF]
				^ T7[(int)(h4 >> 56) & 0xFF];
			t4 = T0[(int)h4 & 0xFF]
				^ T1[((int)h3 >> 8) & 0xFF]
				^ T2[((int)h2 >> 16) & 0xFF]
				^ T3[((int)h1 >> 24) & 0xFF]
				^ T4[(int)(h0 >> 32) & 0xFF]
				^ T5[(int)(h7 >> 40) & 0xFF]
				^ T6[(int)(h6 >> 48) & 0xFF]
				^ T7[(int)(h5 >> 56) & 0xFF];
			t5 = T0[(int)h5 & 0xFF]
				^ T1[((int)h4 >> 8) & 0xFF]
				^ T2[((int)h3 >> 16) & 0xFF]
				^ T3[((int)h2 >> 24) & 0xFF]
				^ T4[(int)(h1 >> 32) & 0xFF]
				^ T5[(int)(h0 >> 40) & 0xFF]
				^ T6[(int)(h7 >> 48) & 0xFF]
				^ T7[(int)(h6 >> 56) & 0xFF];
			t6 = T0[(int)h6 & 0xFF]
				^ T1[((int)h5 >> 8) & 0xFF]
				^ T2[((int)h4 >> 16) & 0xFF]
				^ T3[((int)h3 >> 24) & 0xFF]
				^ T4[(int)(h2 >> 32) & 0xFF]
				^ T5[(int)(h1 >> 40) & 0xFF]
				^ T6[(int)(h0 >> 48) & 0xFF]
				^ T7[(int)(h7 >> 56) & 0xFF];
			t7 = T0[(int)h7 & 0xFF]
				^ T1[((int)h6 >> 8) & 0xFF]
				^ T2[((int)h5 >> 16) & 0xFF]
				^ T3[((int)h4 >> 24) & 0xFF]
				^ T4[(int)(h3 >> 32) & 0xFF]
				^ T5[(int)(h2 >> 40) & 0xFF]
				^ T6[(int)(h1 >> 48) & 0xFF]
				^ T7[(int)(h0 >> 56) & 0xFF];
			h0 = t0;
			h1 = t1;
			h2 = t2;
			h3 = t3;
			h4 = t4;
			h5 = t5;
			h6 = t6;
			h7 = t7;
			t0 = T0[(int)n0 & 0xFF]
				^ T1[((int)n7 >> 8) & 0xFF]
				^ T2[((int)n6 >> 16) & 0xFF]
				^ T3[((int)n5 >> 24) & 0xFF]
				^ T4[(int)(n4 >> 32) & 0xFF]
				^ T5[(int)(n3 >> 40) & 0xFF]
				^ T6[(int)(n2 >> 48) & 0xFF]
				^ T7[(int)(n1 >> 56) & 0xFF]
				^ h0;
			t1 = T0[(int)n1 & 0xFF]
				^ T1[((int)n0 >> 8) & 0xFF]
				^ T2[((int)n7 >> 16) & 0xFF]
				^ T3[((int)n6 >> 24) & 0xFF]
				^ T4[(int)(n5 >> 32) & 0xFF]
				^ T5[(int)(n4 >> 40) & 0xFF]
				^ T6[(int)(n3 >> 48) & 0xFF]
				^ T7[(int)(n2 >> 56) & 0xFF]
				^ h1;
			t2 = T0[(int)n2 & 0xFF]
				^ T1[((int)n1 >> 8) & 0xFF]
				^ T2[((int)n0 >> 16) & 0xFF]
				^ T3[((int)n7 >> 24) & 0xFF]
				^ T4[(int)(n6 >> 32) & 0xFF]
				^ T5[(int)(n5 >> 40) & 0xFF]
				^ T6[(int)(n4 >> 48) & 0xFF]
				^ T7[(int)(n3 >> 56) & 0xFF]
				^ h2;
			t3 = T0[(int)n3 & 0xFF]
				^ T1[((int)n2 >> 8) & 0xFF]
				^ T2[((int)n1 >> 16) & 0xFF]
				^ T3[((int)n0 >> 24) & 0xFF]
				^ T4[(int)(n7 >> 32) & 0xFF]
				^ T5[(int)(n6 >> 40) & 0xFF]
				^ T6[(int)(n5 >> 48) & 0xFF]
				^ T7[(int)(n4 >> 56) & 0xFF]
				^ h3;
			t4 = T0[(int)n4 & 0xFF]
				^ T1[((int)n3 >> 8) & 0xFF]
				^ T2[((int)n2 >> 16) & 0xFF]
				^ T3[((int)n1 >> 24) & 0xFF]
				^ T4[(int)(n0 >> 32) & 0xFF]
				^ T5[(int)(n7 >> 40) & 0xFF]
				^ T6[(int)(n6 >> 48) & 0xFF]
				^ T7[(int)(n5 >> 56) & 0xFF]
				^ h4;
			t5 = T0[(int)n5 & 0xFF]
				^ T1[((int)n4 >> 8) & 0xFF]
				^ T2[((int)n3 >> 16) & 0xFF]
				^ T3[((int)n2 >> 24) & 0xFF]
				^ T4[(int)(n1 >> 32) & 0xFF]
				^ T5[(int)(n0 >> 40) & 0xFF]
				^ T6[(int)(n7 >> 48) & 0xFF]
				^ T7[(int)(n6 >> 56) & 0xFF]
				^ h5;
			t6 = T0[(int)n6 & 0xFF]
				^ T1[((int)n5 >> 8) & 0xFF]
				^ T2[((int)n4 >> 16) & 0xFF]
				^ T3[((int)n3 >> 24) & 0xFF]
				^ T4[(int)(n2 >> 32) & 0xFF]
				^ T5[(int)(n1 >> 40) & 0xFF]
				^ T6[(int)(n0 >> 48) & 0xFF]
				^ T7[(int)(n7 >> 56) & 0xFF]
				^ h6;
			t7 = T0[(int)n7 & 0xFF]
				^ T1[((int)n6 >> 8) & 0xFF]
				^ T2[((int)n5 >> 16) & 0xFF]
				^ T3[((int)n4 >> 24) & 0xFF]
				^ T4[(int)(n3 >> 32) & 0xFF]
				^ T5[(int)(n2 >> 40) & 0xFF]
				^ T6[(int)(n1 >> 48) & 0xFF]
				^ T7[(int)(n0 >> 56) & 0xFF]
				^ h7;
			n0 = t0;
			n1 = t1;
			n2 = t2;
			n3 = t3;
			n4 = t4;
			n5 = t5;
			n6 = t6;
			n7 = t7;
		}
		state0 ^= n0 ^ sn0;
		state1 ^= n1 ^ sn1;
		state2 ^= n2 ^ sn2;
		state3 ^= n3 ^ sn3;
		state4 ^= n4 ^ sn4;
		state5 ^= n5 ^ sn5;
		state6 ^= n6 ^ sn6;
		state7 ^= n7 ^ sn7;
	}
}
