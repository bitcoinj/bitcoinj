// $Id: BMWBigCore.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * This class implements BMW-384 and BMW-512.
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

abstract class BMWBigCore extends DigestEngine {

	private long[] M, H, H2, Q, W;

	/**
	 * Create the object.
	 */
	BMWBigCore()
	{
	}

	/** @see Digest */
	public int getBlockLength()
	{
		return 128;
	}

	/** @see DigestEngine */
	protected Digest copyState(BMWBigCore dst)
	{
		System.arraycopy(H, 0, dst.H, 0, H.length);
		return super.copyState(dst);
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		long[] iv = getInitVal();
		System.arraycopy(iv, 0, H, 0, iv.length);
	}

	abstract long[] getInitVal();

	private static final long[] FINAL = {
		0xaaaaaaaaaaaaaaa0L, 0xaaaaaaaaaaaaaaa1L,
		0xaaaaaaaaaaaaaaa2L, 0xaaaaaaaaaaaaaaa3L,
		0xaaaaaaaaaaaaaaa4L, 0xaaaaaaaaaaaaaaa5L,
		0xaaaaaaaaaaaaaaa6L, 0xaaaaaaaaaaaaaaa7L,
		0xaaaaaaaaaaaaaaa8L, 0xaaaaaaaaaaaaaaa9L,
		0xaaaaaaaaaaaaaaaaL, 0xaaaaaaaaaaaaaaabL,
		0xaaaaaaaaaaaaaaacL, 0xaaaaaaaaaaaaaaadL,
		0xaaaaaaaaaaaaaaaeL, 0xaaaaaaaaaaaaaaafL
	};

	private static final long[] K = {
		16L * 0x0555555555555555L, 17L * 0x0555555555555555L,
		18L * 0x0555555555555555L, 19L * 0x0555555555555555L,
		20L * 0x0555555555555555L, 21L * 0x0555555555555555L,
		22L * 0x0555555555555555L, 23L * 0x0555555555555555L,
		24L * 0x0555555555555555L, 25L * 0x0555555555555555L,
		26L * 0x0555555555555555L, 27L * 0x0555555555555555L,
		28L * 0x0555555555555555L, 29L * 0x0555555555555555L,
		30L * 0x0555555555555555L, 31L * 0x0555555555555555L
	};

	private void compress(long[] m)
	{
		long[] h = H;
		long[] q = Q;
		long[] w = W;
		w[0] = (m[5] ^ h[5]) - (m[7] ^ h[7]) + (m[10] ^ h[10])
			+ (m[13] ^ h[13]) + (m[14] ^ h[14]);
		w[1] = (m[6] ^ h[6]) - (m[8] ^ h[8]) + (m[11] ^ h[11])
			+ (m[14] ^ h[14]) - (m[15] ^ h[15]);
		w[2] = (m[0] ^ h[0]) + (m[7] ^ h[7]) + (m[9] ^ h[9])
			- (m[12] ^ h[12]) + (m[15] ^ h[15]);
		w[3] = (m[0] ^ h[0]) - (m[1] ^ h[1]) + (m[8] ^ h[8])
			- (m[10] ^ h[10]) + (m[13] ^ h[13]);
		w[4] = (m[1] ^ h[1]) + (m[2] ^ h[2]) + (m[9] ^ h[9])
			- (m[11] ^ h[11]) - (m[14] ^ h[14]);
		w[5] = (m[3] ^ h[3]) - (m[2] ^ h[2]) + (m[10] ^ h[10])
			- (m[12] ^ h[12]) + (m[15] ^ h[15]);
		w[6] = (m[4] ^ h[4]) - (m[0] ^ h[0]) - (m[3] ^ h[3])
			- (m[11] ^ h[11]) + (m[13] ^ h[13]);
		w[7] = (m[1] ^ h[1]) - (m[4] ^ h[4]) - (m[5] ^ h[5])
			- (m[12] ^ h[12]) - (m[14] ^ h[14]);
		w[8] = (m[2] ^ h[2]) - (m[5] ^ h[5]) - (m[6] ^ h[6])
			+ (m[13] ^ h[13]) - (m[15] ^ h[15]);
		w[9] = (m[0] ^ h[0]) - (m[3] ^ h[3]) + (m[6] ^ h[6])
			- (m[7] ^ h[7]) + (m[14] ^ h[14]);
		w[10] = (m[8] ^ h[8]) - (m[1] ^ h[1]) - (m[4] ^ h[4])
			- (m[7] ^ h[7]) + (m[15] ^ h[15]);
		w[11] = (m[8] ^ h[8]) - (m[0] ^ h[0]) - (m[2] ^ h[2])
			- (m[5] ^ h[5]) + (m[9] ^ h[9]);
		w[12] = (m[1] ^ h[1]) + (m[3] ^ h[3]) - (m[6] ^ h[6])
			- (m[9] ^ h[9]) + (m[10] ^ h[10]);
		w[13] = (m[2] ^ h[2]) + (m[4] ^ h[4]) + (m[7] ^ h[7])
			+ (m[10] ^ h[10]) + (m[11] ^ h[11]);
		w[14] = (m[3] ^ h[3]) - (m[5] ^ h[5]) + (m[8] ^ h[8])
			- (m[11] ^ h[11]) - (m[12] ^ h[12]);
		w[15] = (m[12] ^ h[12]) - (m[4] ^ h[4]) - (m[6] ^ h[6])
			- (m[9] ^ h[9]) + (m[13] ^ h[13]);
		for (int u = 0; u < 15; u += 5) {
			q[u + 0] = ((w[u + 0] >>> 1) ^ (w[u + 0] << 3)
				^ circularLeft(w[u + 0], 4)
				^ circularLeft(w[u + 0], 37)) + h[u + 1];
			q[u + 1] = ((w[u + 1] >>> 1) ^ (w[u + 1] << 2)
				^ circularLeft(w[u + 1], 13)
				^ circularLeft(w[u + 1], 43)) + h[u + 2];
			q[u + 2] = ((w[u + 2] >>> 2) ^ (w[u + 2] << 1)
				^ circularLeft(w[u + 2], 19)
				^ circularLeft(w[u + 2], 53)) + h[u + 3];
			q[u + 3] = ((w[u + 3] >>> 2) ^ (w[u + 3] << 2)
				^ circularLeft(w[u + 3], 28)
				^ circularLeft(w[u + 3], 59)) + h[u + 4];
			q[u + 4] = ((w[u + 4] >>> 1) ^ w[u + 4]) + h[u + 5];
		}
		q[15] = ((w[15] >>> 1) ^ (w[15] << 3)
			^ circularLeft(w[15], 4) ^ circularLeft(w[15], 37))
			+ h[0];

		for (int u = 16; u < 18; u++) {
			q[u] = ((q[u - 16] >>> 1) ^ (q[u - 16] << 2)
				^ circularLeft(q[u - 16], 13)
				^ circularLeft(q[u - 16], 43))
				+ ((q[u - 15] >>> 2) ^ (q[u - 15] << 1)
				^ circularLeft(q[u - 15], 19)
				^ circularLeft(q[u - 15], 53))
				+ ((q[u - 14] >>> 2) ^ (q[u - 14] << 2)
				^ circularLeft(q[u - 14], 28)
				^ circularLeft(q[u - 14], 59))
				+ ((q[u - 13] >>> 1) ^ (q[u - 13] << 3)
				^ circularLeft(q[u - 13], 4)
				^ circularLeft(q[u - 13], 37))
				+ ((q[u - 12] >>> 1) ^ (q[u - 12] << 2)
				^ circularLeft(q[u - 12], 13)
				^ circularLeft(q[u - 12], 43))
				+ ((q[u - 11] >>> 2) ^ (q[u - 11] << 1)
				^ circularLeft(q[u - 11], 19)
				^ circularLeft(q[u - 11], 53))
				+ ((q[u - 10] >>> 2) ^ (q[u - 10] << 2)
				^ circularLeft(q[u - 10], 28)
				^ circularLeft(q[u - 10], 59))
				+ ((q[u - 9] >>> 1) ^ (q[u - 9] << 3)
				^ circularLeft(q[u - 9], 4)
				^ circularLeft(q[u - 9], 37))
				+ ((q[u - 8] >>> 1) ^ (q[u - 8] << 2)
				^ circularLeft(q[u - 8], 13)
				^ circularLeft(q[u - 8], 43))
				+ ((q[u - 7] >>> 2) ^ (q[u - 7] << 1)
				^ circularLeft(q[u - 7], 19)
				^ circularLeft(q[u - 7], 53))
				+ ((q[u - 6] >>> 2) ^ (q[u - 6] << 2)
				^ circularLeft(q[u - 6], 28)
				^ circularLeft(q[u - 6], 59))
				+ ((q[u - 5] >>> 1) ^ (q[u - 5] << 3)
				^ circularLeft(q[u - 5], 4)
				^ circularLeft(q[u - 5], 37))
				+ ((q[u - 4] >>> 1) ^ (q[u - 4] << 2)
				^ circularLeft(q[u - 4], 13)
				^ circularLeft(q[u - 4], 43))
				+ ((q[u - 3] >>> 2) ^ (q[u - 3] << 1)
				^ circularLeft(q[u - 3], 19)
				^ circularLeft(q[u - 3], 53))
				+ ((q[u - 2] >>> 2) ^ (q[u - 2] << 2)
				^ circularLeft(q[u - 2], 28)
				^ circularLeft(q[u - 2], 59))
				+ ((q[u - 1] >>> 1) ^ (q[u - 1] << 3)
				^ circularLeft(q[u - 1], 4)
				^ circularLeft(q[u - 1], 37))
				+ ((circularLeft(m[(u - 16 + 0) & 15],
					((u - 16 + 0) & 15) + 1)
				+ circularLeft(m[(u - 16 + 3) & 15],
					((u - 16 + 3) & 15) + 1)
				- circularLeft(m[(u - 16 + 10) & 15],
					((u - 16 + 10) & 15) + 1)
				+ K[u - 16]) ^ h[(u - 16 + 7) & 15]);
		}
		for (int u = 18; u < 32; u++) {
			q[u] = q[u - 16] + circularLeft(q[u - 15], 5)
				+ q[u - 14] + circularLeft(q[u - 13], 11)
				+ q[u - 12] + circularLeft(q[u - 11], 27)
				+ q[u - 10] + circularLeft(q[u - 9], 32)
				+ q[u - 8] + circularLeft(q[u - 7], 37)
				+ q[u - 6] + circularLeft(q[u - 5], 43)
				+ q[u - 4] + circularLeft(q[u - 3], 53)
				+ ((q[u - 2] >>> 1) ^ q[u - 2])
				+ ((q[u - 1] >>> 2) ^ q[u - 1])
				+ ((circularLeft(m[(u - 16 + 0) & 15],
					((u - 16 + 0) & 15) + 1)
				+ circularLeft(m[(u - 16 + 3) & 15],
					((u - 16 + 3) & 15) + 1)
				- circularLeft(m[(u - 16 + 10) & 15],
					((u - 16 + 10) & 15) + 1)
				+ K[u - 16]) ^ h[(u - 16 + 7) & 15]);
		}

		long xl = q[16] ^ q[17] ^ q[18] ^ q[19]
			^ q[20] ^ q[21] ^ q[22] ^ q[23];
		long xh = xl ^ q[24] ^ q[25] ^ q[26] ^ q[27]
			^ q[28] ^ q[29] ^ q[30] ^ q[31];
		h[0] = ((xh << 5) ^ (q[16] >>> 5) ^ m[0]) + (xl ^ q[24] ^ q[0]);
		h[1] = ((xh >>> 7) ^ (q[17] << 8) ^ m[1]) + (xl ^ q[25] ^ q[1]);
		h[2] = ((xh >>> 5) ^ (q[18] << 5) ^ m[2]) + (xl ^ q[26] ^ q[2]);
		h[3] = ((xh >>> 1) ^ (q[19] << 5) ^ m[3]) + (xl ^ q[27] ^ q[3]);
		h[4] = ((xh >>> 3) ^ (q[20] << 0) ^ m[4]) + (xl ^ q[28] ^ q[4]);
		h[5] = ((xh << 6) ^ (q[21] >>> 6) ^ m[5]) + (xl ^ q[29] ^ q[5]);
		h[6] = ((xh >>> 4) ^ (q[22] << 6) ^ m[6]) + (xl ^ q[30] ^ q[6]);
		h[7] = ((xh >>> 11) ^ (q[23] << 2) ^ m[7])
			+ (xl ^ q[31] ^ q[7]);
		h[8] = circularLeft(h[4], 9) + (xh ^ q[24] ^ m[8])
			+ ((xl << 8) ^ q[23] ^ q[8]);
		h[9] = circularLeft(h[5], 10) + (xh ^ q[25] ^ m[9])
			+ ((xl >>> 6) ^ q[16] ^ q[9]);
		h[10] = circularLeft(h[6], 11) + (xh ^ q[26] ^ m[10])
			+ ((xl << 6) ^ q[17] ^ q[10]);
		h[11] = circularLeft(h[7], 12) + (xh ^ q[27] ^ m[11])
			+ ((xl << 4) ^ q[18] ^ q[11]);
		h[12] = circularLeft(h[0], 13) + (xh ^ q[28] ^ m[12])
			+ ((xl >>> 3) ^ q[19] ^ q[12]);
		h[13] = circularLeft(h[1], 14) + (xh ^ q[29] ^ m[13])
			+ ((xl >>> 4) ^ q[20] ^ q[13]);
		h[14] = circularLeft(h[2], 15) + (xh ^ q[30] ^ m[14])
			+ ((xl >>> 7) ^ q[21] ^ q[14]);
		h[15] = circularLeft(h[3], 16) + (xh ^ q[31] ^ m[15])
			+ ((xl >>> 2) ^ q[22] ^ q[15]);
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		byte[] buf = getBlockBuffer();
		int ptr = flush();
		long bitLen = (getBlockCount() << 10) + (ptr << 3);
		buf[ptr ++] = (byte)0x80;
		if (ptr > 120) {
			for (int i = ptr; i < 128; i ++)
				buf[i] = 0;
			processBlock(buf);
			ptr = 0;
		}
		for (int i = ptr; i < 120; i ++)
			buf[i] = 0;
		encodeLELong(bitLen, buf, 120);
		processBlock(buf);
		long[] tmp = H;
		H = H2;
		H2 = tmp;
		System.arraycopy(FINAL, 0, H, 0, 16);
		compress(H2);
		int outLen = getDigestLength() >>> 3;
		for (int i = 0, j = 16 - outLen; i < outLen; i ++, j ++)
			encodeLELong(H[j], output, outputOffset + 8 * i);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		M = new long[16];
		H = new long[16];
		H2 = new long[16];
		W = new long[16];
		Q = new long[32];
		engineReset();
	}

	/**
	 * Encode the 64-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in little-endian
	 * convention (least significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	private static final void encodeLELong(long val, byte[] buf, int off)
	{
		buf[off + 0] = (byte)val;
		buf[off + 1] = (byte)(val >>> 8);
		buf[off + 2] = (byte)(val >>> 16);
		buf[off + 3] = (byte)(val >>> 24);
		buf[off + 4] = (byte)(val >>> 32);
		buf[off + 5] = (byte)(val >>> 40);
		buf[off + 6] = (byte)(val >>> 48);
		buf[off + 7] = (byte)(val >>> 56);
	}

	/**
	 * Decode a 64-bit little-endian word from the array {@code buf}
	 * at offset {@code off}.
	 *
	 * @param buf   the source buffer
	 * @param off   the source offset
	 * @return  the decoded value
	 */
	private static final long decodeLELong(byte[] buf, int off)
	{
		return (buf[off + 0] & 0xFFL)
			| ((buf[off + 1] & 0xFFL) << 8)
			| ((buf[off + 2] & 0xFFL) << 16)
			| ((buf[off + 3] & 0xFFL) << 24)
			| ((buf[off + 4] & 0xFFL) << 32)
			| ((buf[off + 5] & 0xFFL) << 40)
			| ((buf[off + 6] & 0xFFL) << 48)
			| ((buf[off + 7] & 0xFFL) << 56);
	}

	/**
	 * Perform a circular rotation by {@code n} to the left
	 * of the 64-bit word {@code x}. The {@code n} parameter
	 * must lie between 1 and 63 (inclusive).
	 *
	 * @param x   the value to rotate
	 * @param n   the rotation count (between 1 and 63)
	 * @return  the rotated value
	*/
	private static final long circularLeft(long x, int n)
	{
		return (x << n) | (x >>> (64 - n));
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		for (int i = 0; i < 16; i ++)
			M[i] = decodeLELong(data, i * 8);
		compress(M);
	}

	/** @see Digest */
	public String toString()
	{
		return "BMW-" + (getDigestLength() << 3);
	}
}
