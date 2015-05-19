// $Id: BLAKEBigCore.java 252 2011-06-07 17:55:14Z tp $

package fr.cryptohash;

/**
 * This class implements BLAKE-384 and BLAKE-512, which differ only by
 * the IV, output length, and one bit in the padding.
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
 * @version   $Revision: 252 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class BLAKEBigCore extends DigestEngine {

	private static final int[] SIGMA = {
		 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
		14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3,
		11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4,
		 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8,
		 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13,
		 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9,
		12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11,
		13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10,
		 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5,
		10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0,
		 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
		14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3,
		11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4,
		 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8,
		 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13,
		 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9
	};

	private static final long[] CB = {
		0x243F6A8885A308D3L, 0x13198A2E03707344L,
		0xA4093822299F31D0L, 0x082EFA98EC4E6C89L,
		0x452821E638D01377L, 0xBE5466CF34E90C6CL,
		0xC0AC29B7C97C50DDL, 0x3F84D5B5B5470917L,
		0x9216D5D98979FB1BL, 0xD1310BA698DFB5ACL,
		0x2FFD72DBD01ADFB7L, 0xB8E1AFED6A267E96L,
		0xBA7C9045F12C7F99L, 0x24A19947B3916CF7L,
		0x0801F2E2858EFC16L, 0x636920D871574E69L
	};

	private long h0, h1, h2, h3, h4, h5, h6, h7;
	private long s0, s1, s2, s3;
	private long t0, t1;
	private long[] tmpM;
	private byte[] tmpBuf;

	/**
	 * Create the object.
	 */
	BLAKEBigCore()
	{
	}

	/** @see Digest */
	public int getBlockLength()
	{
		return 128;
	}

	/** @see DigestEngine */
	protected Digest copyState(BLAKEBigCore dst)
	{
		dst.h0 = h0;
		dst.h1 = h1;
		dst.h2 = h2;
		dst.h3 = h3;
		dst.h4 = h4;
		dst.h5 = h5;
		dst.h6 = h6;
		dst.h7 = h7;
		dst.s0 = s0;
		dst.s1 = s1;
		dst.s2 = s2;
		dst.s3 = s3;
		dst.t0 = t0;
		dst.t1 = t1;
		return super.copyState(dst);
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		long[] iv = getInitVal();
		h0 = iv[0];
		h1 = iv[1];
		h2 = iv[2];
		h3 = iv[3];
		h4 = iv[4];
		h5 = iv[5];
		h6 = iv[6];
		h7 = iv[7];
		s0 = s1 = s2 = s3 = 0;
		t0 = t1 = 0;
	}

	/**
	 * Get the initial value for this algorithm.
	 *
	 * @return  the initial value (eight 64-bit words)
	 */
	abstract long[] getInitVal();

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		int ptr = flush();
		int bitLen = ptr << 3;
		long th = t1;
		long tl = t0 + bitLen;
		tmpBuf[ptr] = (byte)0x80;
		if (ptr == 0) {
			t0 = 0xFFFFFFFFFFFFFC00L;
			t1 = 0xFFFFFFFFFFFFFFFFL;
		} else if (t0 == 0) {
			t0 = (int)0xFFFFFFFFFFFFFC00L + bitLen;
			t1 --;
		} else {
			t0 -= 1024 - bitLen;
		}
		if (ptr < 112) {
			for (int i = ptr + 1; i < 112; i ++)
				tmpBuf[i] = 0x00;
			if (getDigestLength() == 64)
				tmpBuf[111] |= 0x01;
			encodeBELong(th, tmpBuf, 112);
			encodeBELong(tl, tmpBuf, 120);
			update(tmpBuf, ptr, 128 - ptr);
		} else {
			for (int i = ptr + 1; i < 128; i ++)
				tmpBuf[i] = 0;
			update(tmpBuf, ptr, 128 - ptr);
			t0 = 0xFFFFFFFFFFFFFC00L;
			t1 = 0xFFFFFFFFFFFFFFFFL;
			for (int i = 0; i < 112; i ++)
				tmpBuf[i] = 0x00;
			if (getDigestLength() == 64)
				tmpBuf[111] = 0x01;
			encodeBELong(th, tmpBuf, 112);
			encodeBELong(tl, tmpBuf, 120);
			update(tmpBuf, 0, 128);
		}
		encodeBELong(h0, output, outputOffset +  0);
		encodeBELong(h1, output, outputOffset +  8);
		encodeBELong(h2, output, outputOffset + 16);
		encodeBELong(h3, output, outputOffset + 24);
		encodeBELong(h4, output, outputOffset + 32);
		encodeBELong(h5, output, outputOffset + 40);
		if (getDigestLength() == 64) {
			encodeBELong(h6, output, outputOffset + 48);
			encodeBELong(h7, output, outputOffset + 56);
		}
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		tmpM = new long[16];
		tmpBuf = new byte[128];
		engineReset();
	}

	/**
	 * Encode the 64-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in big-endian
	 * convention (most significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	private static final void encodeBELong(long val, byte[] buf, int off)
	{
		buf[off + 0] = (byte)(val >>> 56);
		buf[off + 1] = (byte)(val >>> 48);
		buf[off + 2] = (byte)(val >>> 40);
		buf[off + 3] = (byte)(val >>> 32);
		buf[off + 4] = (byte)(val >>> 24);
		buf[off + 5] = (byte)(val >>> 16);
		buf[off + 6] = (byte)(val >>> 8);
		buf[off + 7] = (byte)val;
	}

	/**
	 * Decode a 64-bit big-endian word from the array {@code buf}
	 * at offset {@code off}.
	 *
	 * @param buf   the source buffer
	 * @param off   the source offset
	 * @return  the decoded value
	 */
	private static final long decodeBELong(byte[] buf, int off)
	{
		return ((long)(buf[off] & 0xFF) << 56)
			| ((long)(buf[off + 1] & 0xFF) << 48)
			| ((long)(buf[off + 2] & 0xFF) << 40)
			| ((long)(buf[off + 3] & 0xFF) << 32)
			| ((long)(buf[off + 4] & 0xFF) << 24)
			| ((long)(buf[off + 5] & 0xFF) << 16)
			| ((long)(buf[off + 6] & 0xFF) << 8)
			| (long)(buf[off + 7] & 0xFF);
	}

	/**
	 * Perform a circular rotation by {@code n} to the right
	 * of the 64-bit word {@code x}. The {@code n} parameter
	 * must lie between 1 and 63 (inclusive).
	 *
	 * @param x   the value to rotate
	 * @param n   the rotation count (between 1 and 63)
	 * @return  the rotated value
	*/
	static private long circularRight(long x, int n)
	{
		return (x >>> n) | (x << (64 - n));
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		t0 += 1024;
		if ((t0 & ~0x3FF) == 0)
			t1 ++;
		long v0 = h0;
		long v1 = h1;
		long v2 = h2;
		long v3 = h3;
		long v4 = h4;
		long v5 = h5;
		long v6 = h6;
		long v7 = h7;
		long v8 = s0 ^ 0x243F6A8885A308D3L;
		long v9 = s1 ^ 0x13198A2E03707344L;
		long vA = s2 ^ 0xA4093822299F31D0L;
		long vB = s3 ^ 0x082EFA98EC4E6C89L;
		long vC = t0 ^ 0x452821E638D01377L;
		long vD = t0 ^ 0xBE5466CF34E90C6CL;
		long vE = t1 ^ 0xC0AC29B7C97C50DDL;
		long vF = t1 ^ 0x3F84D5B5B5470917L;
		long[] m = tmpM;
		for (int i = 0; i < 16; i ++)
			m[i] = decodeBELong(data, 8 * i);
		for (int r = 0; r < 16; r ++) {
			int o0 = SIGMA[(r << 4) + 0x0];
			int o1 = SIGMA[(r << 4) + 0x1];
			v0 += v4 + (m[o0] ^ CB[o1]);
			vC = circularRight(vC ^ v0, 32);
			v8 += vC;
			v4 = circularRight(v4 ^ v8, 25);
			v0 += v4 + (m[o1] ^ CB[o0]);
			vC = circularRight(vC ^ v0, 16);
			v8 += vC;
			v4 = circularRight(v4 ^ v8, 11);
			o0 = SIGMA[(r << 4) + 0x2];
			o1 = SIGMA[(r << 4) + 0x3];
			v1 += v5 + (m[o0] ^ CB[o1]);
			vD = circularRight(vD ^ v1, 32);
			v9 += vD;
			v5 = circularRight(v5 ^ v9, 25);
			v1 += v5 + (m[o1] ^ CB[o0]);
			vD = circularRight(vD ^ v1, 16);
			v9 += vD;
			v5 = circularRight(v5 ^ v9, 11);
			o0 = SIGMA[(r << 4) + 0x4];
			o1 = SIGMA[(r << 4) + 0x5];
			v2 += v6 + (m[o0] ^ CB[o1]);
			vE = circularRight(vE ^ v2, 32);
			vA += vE;
			v6 = circularRight(v6 ^ vA, 25);
			v2 += v6 + (m[o1] ^ CB[o0]);
			vE = circularRight(vE ^ v2, 16);
			vA += vE;
			v6 = circularRight(v6 ^ vA, 11);
			o0 = SIGMA[(r << 4) + 0x6];
			o1 = SIGMA[(r << 4) + 0x7];
			v3 += v7 + (m[o0] ^ CB[o1]);
			vF = circularRight(vF ^ v3, 32);
			vB += vF;
			v7 = circularRight(v7 ^ vB, 25);
			v3 += v7 + (m[o1] ^ CB[o0]);
			vF = circularRight(vF ^ v3, 16);
			vB += vF;
			v7 = circularRight(v7 ^ vB, 11);
			o0 = SIGMA[(r << 4) + 0x8];
			o1 = SIGMA[(r << 4) + 0x9];
			v0 += v5 + (m[o0] ^ CB[o1]);
			vF = circularRight(vF ^ v0, 32);
			vA += vF;
			v5 = circularRight(v5 ^ vA, 25);
			v0 += v5 + (m[o1] ^ CB[o0]);
			vF = circularRight(vF ^ v0, 16);
			vA += vF;
			v5 = circularRight(v5 ^ vA, 11);
			o0 = SIGMA[(r << 4) + 0xA];
			o1 = SIGMA[(r << 4) + 0xB];
			v1 += v6 + (m[o0] ^ CB[o1]);
			vC = circularRight(vC ^ v1, 32);
			vB += vC;
			v6 = circularRight(v6 ^ vB, 25);
			v1 += v6 + (m[o1] ^ CB[o0]);
			vC = circularRight(vC ^ v1, 16);
			vB += vC;
			v6 = circularRight(v6 ^ vB, 11);
			o0 = SIGMA[(r << 4) + 0xC];
			o1 = SIGMA[(r << 4) + 0xD];
			v2 += v7 + (m[o0] ^ CB[o1]);
			vD = circularRight(vD ^ v2, 32);
			v8 += vD;
			v7 = circularRight(v7 ^ v8, 25);
			v2 += v7 + (m[o1] ^ CB[o0]);
			vD = circularRight(vD ^ v2, 16);
			v8 += vD;
			v7 = circularRight(v7 ^ v8, 11);
			o0 = SIGMA[(r << 4) + 0xE];
			o1 = SIGMA[(r << 4) + 0xF];
			v3 += v4 + (m[o0] ^ CB[o1]);
			vE = circularRight(vE ^ v3, 32);
			v9 += vE;
			v4 = circularRight(v4 ^ v9, 25);
			v3 += v4 + (m[o1] ^ CB[o0]);
			vE = circularRight(vE ^ v3, 16);
			v9 += vE;
			v4 = circularRight(v4 ^ v9, 11);
		}
		h0 ^= s0 ^ v0 ^ v8;
		h1 ^= s1 ^ v1 ^ v9;
		h2 ^= s2 ^ v2 ^ vA;
		h3 ^= s3 ^ v3 ^ vB;
		h4 ^= s0 ^ v4 ^ vC;
		h5 ^= s1 ^ v5 ^ vD;
		h6 ^= s2 ^ v6 ^ vE;
		h7 ^= s3 ^ v7 ^ vF;
	}

	/** @see Digest */
	public String toString()
	{
		return "BLAKE-" + (getDigestLength() << 3);
	}
}
