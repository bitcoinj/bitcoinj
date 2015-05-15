// $Id: SIMDSmallCore.java 241 2010-06-21 15:04:01Z tp $

package fr.cryptohash;

/**
 * This class implements SIMD-224 and SIMD-256.
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
 * @version   $Revision: 241 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class SIMDSmallCore extends DigestEngine {

	private int[] state;
	private int[] q, w, tmpState, tA;

	/**
	 * Create the object.
	 */
	SIMDSmallCore()
	{
	}

	/** @see Digest */
	public int getBlockLength()
	{
		return 64;
	}

	/** @see DigestEngine */
	protected Digest copyState(SIMDSmallCore dst)
	{
		System.arraycopy(state, 0, dst.state, 0, 16);
		return super.copyState(dst);
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		int[] iv = getInitVal();
		System.arraycopy(iv, 0, state, 0, 16);
	}

	/**
	 * Get the initial value for this algorithm.
	 *
	 * @return  the initial value (eight 32-bit words)
	 */
	abstract int[] getInitVal();

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		int ptr = flush();
		byte[] buf = getBlockBuffer();
		if (ptr != 0) {
			for (int i = ptr; i < 64; i ++)
				buf[i] = 0x00;
			compress(buf, false);
		}
		long count = (getBlockCount() << 9) + (long)(ptr << 3);
		encodeLEInt((int)count, buf, 0);
		encodeLEInt((int)(count >> 32), buf, 4);
		for (int i = 8; i < 64; i ++)
			buf[i] = 0x00;
		compress(buf, true);
		int n = getDigestLength() >>> 2;
		for (int i = 0; i < n; i ++)
			encodeLEInt(state[i], output, outputOffset + (i << 2));
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		state = new int[16];
		q = new int[128];
		w = new int[32];
		tmpState = new int[16];
		tA = new int[4];
		engineReset();
	}

	/**
	 * Encode the 32-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in little-endian
	 * convention (least significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	private static final void encodeLEInt(int val, byte[] buf, int off)
	{
		buf[off + 0] = (byte)val;
		buf[off + 1] = (byte)(val >>> 8);
		buf[off + 2] = (byte)(val >>> 16);
		buf[off + 3] = (byte)(val >>> 24);
	}

	/**
	 * Decode a 32-bit little-endian word from the array {@code buf}
	 * at offset {@code off}.
	 *
	 * @param buf   the source buffer
	 * @param off   the source offset
	 * @return  the decoded value
	 */
	private static final int decodeLEInt(byte[] buf, int off)
	{
		return ((buf[off + 3] & 0xFF) << 24)
			| ((buf[off + 2] & 0xFF) << 16)
			| ((buf[off + 1] & 0xFF) << 8)
			| (buf[off] & 0xFF);
	}

	/**
	 * Perform a circular rotation by {@code n} to the left
	 * of the 32-bit word {@code x}. The {@code n} parameter
	 * must lie between 1 and 31 (inclusive).
	 *
	 * @param x   the value to rotate
	 * @param n   the rotation count (between 1 and 31)
	 * @return  the rotated value
	*/
	static private int circularLeft(int x, int n)
	{
		return (x >>> (32 - n)) | (x << n);
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		compress(data, false);
	}

	private static final int[] alphaTab = {
		  1,  41, 139,  45,  46,  87, 226,  14,  60, 147, 116, 130,
		190,  80, 196,  69,   2,  82,  21,  90,  92, 174, 195,  28,
		120,  37, 232,   3, 123, 160, 135, 138,   4, 164,  42, 180,
		184,  91, 133,  56, 240,  74, 207,   6, 246,  63,  13,  19,
		  8,  71,  84, 103, 111, 182,   9, 112, 223, 148, 157,  12,
		235, 126,  26,  38,  16, 142, 168, 206, 222, 107,  18, 224,
		189,  39,  57,  24, 213, 252,  52,  76,  32,  27,  79, 155,
		187, 214,  36, 191, 121,  78, 114,  48, 169, 247, 104, 152,
		 64,  54, 158,  53, 117, 171,  72, 125, 242, 156, 228,  96,
		 81, 237, 208,  47, 128, 108,  59, 106, 234,  85, 144, 250,
		227,  55, 199, 192, 162, 217, 159,  94, 256, 216, 118, 212,
		211, 170,  31, 243, 197, 110, 141, 127,  67, 177,  61, 188,
		255, 175, 236, 167, 165,  83,  62, 229, 137, 220,  25, 254,
		134,  97, 122, 119, 253,  93, 215,  77,  73, 166, 124, 201,
		 17, 183,  50, 251,  11, 194, 244, 238, 249, 186, 173, 154,
		146,  75, 248, 145,  34, 109, 100, 245,  22, 131, 231, 219,
		241, 115,  89,  51,  35, 150, 239,  33,  68, 218, 200, 233,
		 44,   5, 205, 181, 225, 230, 178, 102,  70,  43, 221,  66,
		136, 179, 143, 209,  88,  10, 153, 105, 193, 203,  99, 204,
		140,  86, 185, 132,  15, 101,  29, 161, 176,  20,  49, 210,
		129, 149, 198, 151,  23, 172, 113,   7,  30, 202,  58,  65,
		 95,  40,  98, 163
	};

	private static final int[] yoffN = {
		  1,  98,  95,  58,  30, 113,  23, 198, 129,  49, 176,  29,
		 15, 185, 140,  99, 193, 153,  88, 143, 136, 221,  70, 178,
		225, 205,  44, 200,  68, 239,  35,  89, 241, 231,  22, 100,
		 34, 248, 146, 173, 249, 244,  11,  50,  17, 124,  73, 215,
		253, 122, 134,  25, 137,  62, 165, 236, 255,  61,  67, 141,
		197,  31, 211, 118, 256, 159, 162, 199, 227, 144, 234,  59,
		128, 208,  81, 228, 242,  72, 117, 158,  64, 104, 169, 114,
		121,  36, 187,  79,  32,  52, 213,  57, 189,  18, 222, 168,
		 16,  26, 235, 157, 223,   9, 111,  84,   8,  13, 246, 207,
		240, 133, 184,  42,   4, 135, 123, 232, 120, 195,  92,  21,
		  2, 196, 190, 116,  60, 226,  46, 139
	};

	private static final int[] yoffF = {
		  2, 156, 118, 107,  45, 212, 111, 162,  97, 249, 211,   3,
		 49, 101, 151, 223, 189, 178, 253, 204,  76,  82, 232,  65,
		 96, 176, 161,  47, 189,  61, 248, 107,   0, 131, 133, 113,
		 17,  33,  12, 111, 251, 103,  57, 148,  47,  65, 249, 143,
		189,   8, 204, 230, 205, 151, 187, 227, 247, 111, 140,   6,
		 77,  10,  21, 149, 255, 101, 139, 150, 212,  45, 146,  95,
		160,   8,  46, 254, 208, 156, 106,  34,  68,  79,   4,  53,
		181, 175,  25, 192, 161,  81,  96, 210,  68, 196,   9, 150,
		  0, 126, 124, 144, 240, 224, 245, 146,   6, 154, 200, 109,
		210, 192,   8, 114,  68, 249,  53,  27,  52, 106,  70,  30,
		 10, 146, 117, 251, 180, 247, 236, 108
	};

	private final void fft32(byte[] x, int xb, int xs, int qoff)
	{
		int xd = xs << 1;
		{
			int d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7;
			int d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7;
			{
				int x0 = x[xb] & 0xFF;
				int x1 = x[xb + 2 * xd] & 0xFF;
				int x2 = x[xb + 4 * xd] & 0xFF;
				int x3 = x[xb + 6 * xd] & 0xFF;
				int a0 = x0 + x2;
				int a1 = x0 + (x2 << 4);
				int a2 = x0 - x2;
				int a3 = x0 - (x2 << 4);
				int b0 = x1 + x3;
				int b1 = ((((x1 << 2) + (x3 << 6)) & 0xFF)
					- (((x1 << 2) + (x3 << 6)) >> 8));
				int b2 = (x1 << 4) - (x3 << 4);
				int b3 = ((((x1 << 6) + (x3 << 2)) & 0xFF)
					- (((x1 << 6) + (x3 << 2)) >> 8));
				d1_0 = a0 + b0;
				d1_1 = a1 + b1;
				d1_2 = a2 + b2;
				d1_3 = a3 + b3;
				d1_4 = a0 - b0;
				d1_5 = a1 - b1;
				d1_6 = a2 - b2;
				d1_7 = a3 - b3;
			}
			{
				int x0 = x[xb + xd] & 0xFF;
				int x1 = x[xb + 3 * xd] & 0xFF;
				int x2 = x[xb + 5 * xd] & 0xFF;
				int x3 = x[xb + 7 * xd] & 0xFF;
				int a0 = x0 + x2;
				int a1 = x0 + (x2 << 4);
				int a2 = x0 - x2;
				int a3 = x0 - (x2 << 4);
				int b0 = x1 + x3;
				int b1 = ((((x1 << 2) + (x3 << 6)) & 0xFF)
					- (((x1 << 2) + (x3 << 6)) >> 8));
				int b2 = (x1 << 4) - (x3 << 4);
				int b3 = ((((x1 << 6) + (x3 << 2)) & 0xFF)
					- (((x1 << 6) + (x3 << 2)) >> 8));
				d2_0 = a0 + b0;
				d2_1 = a1 + b1;
				d2_2 = a2 + b2;
				d2_3 = a3 + b3;
				d2_4 = a0 - b0;
				d2_5 = a1 - b1;
				d2_6 = a2 - b2;
				d2_7 = a3 - b3;
			}
			q[qoff +  0] = d1_0 + d2_0;
			q[qoff +  1] = d1_1 + (d2_1 << 1);
			q[qoff +  2] = d1_2 + (d2_2 << 2);
			q[qoff +  3] = d1_3 + (d2_3 << 3);
			q[qoff +  4] = d1_4 + (d2_4 << 4);
			q[qoff +  5] = d1_5 + (d2_5 << 5);
			q[qoff +  6] = d1_6 + (d2_6 << 6);
			q[qoff +  7] = d1_7 + (d2_7 << 7);
			q[qoff +  8] = d1_0 - d2_0;
			q[qoff +  9] = d1_1 - (d2_1 << 1);
			q[qoff + 10] = d1_2 - (d2_2 << 2);
			q[qoff + 11] = d1_3 - (d2_3 << 3);
			q[qoff + 12] = d1_4 - (d2_4 << 4);
			q[qoff + 13] = d1_5 - (d2_5 << 5);
			q[qoff + 14] = d1_6 - (d2_6 << 6);
			q[qoff + 15] = d1_7 - (d2_7 << 7);
		}
		{
			int d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7;
			int d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7;
			{
				int x0 = x[xb + xs] & 0xFF;
				int x1 = x[xb + xs + 2 * xd] & 0xFF;
				int x2 = x[xb + xs + 4 * xd] & 0xFF;
				int x3 = x[xb + xs + 6 * xd] & 0xFF;
				int a0 = x0 + x2;
				int a1 = x0 + (x2 << 4);
				int a2 = x0 - x2;
				int a3 = x0 - (x2 << 4);
				int b0 = x1 + x3;
				int b1 = ((((x1 << 2) + (x3 << 6)) & 0xFF)
					- (((x1 << 2) + (x3 << 6)) >> 8));
				int b2 = (x1 << 4) - (x3 << 4);
				int b3 = ((((x1 << 6) + (x3 << 2)) & 0xFF)
					- (((x1 << 6) + (x3 << 2)) >> 8));
				d1_0 = a0 + b0;
				d1_1 = a1 + b1;
				d1_2 = a2 + b2;
				d1_3 = a3 + b3;
				d1_4 = a0 - b0;
				d1_5 = a1 - b1;
				d1_6 = a2 - b2;
				d1_7 = a3 - b3;
			}
			{
				int x0 = x[xb + xs + xd] & 0xFF;
				int x1 = x[xb + xs + 3 * xd] & 0xFF;
				int x2 = x[xb + xs + 5 * xd] & 0xFF;
				int x3 = x[xb + xs + 7 * xd] & 0xFF;
				int a0 = x0 + x2;
				int a1 = x0 + (x2 << 4);
				int a2 = x0 - x2;
				int a3 = x0 - (x2 << 4);
				int b0 = x1 + x3;
				int b1 = ((((x1 << 2) + (x3 << 6)) & 0xFF)
					- (((x1 << 2) + (x3 << 6)) >> 8));
				int b2 = (x1 << 4) - (x3 << 4);
				int b3 = ((((x1 << 6) + (x3 << 2)) & 0xFF)
					- (((x1 << 6) + (x3 << 2)) >> 8));
				d2_0 = a0 + b0;
				d2_1 = a1 + b1;
				d2_2 = a2 + b2;
				d2_3 = a3 + b3;
				d2_4 = a0 - b0;
				d2_5 = a1 - b1;
				d2_6 = a2 - b2;
				d2_7 = a3 - b3;
			};
			q[qoff + 16 +  0] = d1_0 + d2_0;
			q[qoff + 16 +  1] = d1_1 + (d2_1 << 1);
			q[qoff + 16 +  2] = d1_2 + (d2_2 << 2);
			q[qoff + 16 +  3] = d1_3 + (d2_3 << 3);
			q[qoff + 16 +  4] = d1_4 + (d2_4 << 4);
			q[qoff + 16 +  5] = d1_5 + (d2_5 << 5);
			q[qoff + 16 +  6] = d1_6 + (d2_6 << 6);
			q[qoff + 16 +  7] = d1_7 + (d2_7 << 7);
			q[qoff + 16 +  8] = d1_0 - d2_0;
			q[qoff + 16 +  9] = d1_1 - (d2_1 << 1);
			q[qoff + 16 + 10] = d1_2 - (d2_2 << 2);
			q[qoff + 16 + 11] = d1_3 - (d2_3 << 3);
			q[qoff + 16 + 12] = d1_4 - (d2_4 << 4);
			q[qoff + 16 + 13] = d1_5 - (d2_5 << 5);
			q[qoff + 16 + 14] = d1_6 - (d2_6 << 6);
			q[qoff + 16 + 15] = d1_7 - (d2_7 << 7);
		}
		int m = q[qoff];
		int n = q[qoff + 16];
		q[qoff] = m + n;
		q[qoff + 16] = m - n;
		for (int u = 0, v = 0; u < 16; u += 4, v += 4 * 8) {
			int t;
			if (u != 0) {
				m = q[qoff + u + 0];
				n = q[qoff + u + 0 + 16];
				t = ((n * alphaTab[v + 0 * 8]) & 0xFFFF)
					+ ((n * alphaTab[v + 0 * 8]) >> 16);
				q[qoff + u + 0] = m + t;
				q[qoff + u + 0 + 16] = m - t;
			}
			m = q[qoff + u + 1];
			n = q[qoff + u + 1 + 16];
			t = (((n * alphaTab[v + 1 * (8)]) & 0xFFFF)
				+ ((n * alphaTab[v + 1 * (8)]) >> 16));
			q[qoff + u + 1] = m + t;
			q[qoff + u + 1 + 16] = m - t;
			m = q[qoff + u + 2];
			n = q[qoff + u + 2 + 16];
			t = (((n * alphaTab[v + 2 * (8)]) & 0xFFFF)
				+ ((n * alphaTab[v + 2 * (8)]) >> 16));
			q[qoff + u + 2] = m + t;
			q[qoff + u + 2 + 16] = m - t;
			m = q[qoff + u + 3];
			n = q[qoff + u + 3 + 16];
			t = (((n * alphaTab[v + 3 * (8)]) & 0xFFFF)
				+ ((n * alphaTab[v + 3 * (8)]) >> 16));
			q[qoff + u + 3] = m + t;
			q[qoff + u + 3 + 16] = m - t;
		}
	}

	private static final int[] pp4k = {
		1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 2
	};

	private static final int[] wsp = {
		 4 << 3,  6 << 3,  0 << 3,  2 << 3,
		 7 << 3,  5 << 3,  3 << 3,  1 << 3,
		15 << 3, 11 << 3, 12 << 3,  8 << 3,
		 9 << 3, 13 << 3, 10 << 3, 14 << 3,
		17 << 3, 18 << 3, 23 << 3, 20 << 3,
		22 << 3, 21 << 3, 16 << 3, 19 << 3,
		30 << 3, 24 << 3, 25 << 3, 31 << 3,
		27 << 3, 29 << 3, 28 << 3, 26 << 3
	};

	private final void oneRound(int isp, int p0, int p1, int p2, int p3)
	{
		int tmp;
		tA[0] = circularLeft(state[0], p0);
		tA[1] = circularLeft(state[1], p0);
		tA[2] = circularLeft(state[2], p0);
		tA[3] = circularLeft(state[3], p0);
		tmp = state[12] + w[0]
			+ (((state[4] ^ state[8]) & state[0]) ^ state[8]);
		state[0] = circularLeft(tmp, p1) + tA[pp4k[isp + 0] ^ 0];
		state[12] = state[8];
		state[8] = state[4];
		state[4] = tA[0];
		tmp = state[13] + w[1]
			+ (((state[5] ^ state[9]) & state[1]) ^ state[9]);
		state[1] = circularLeft(tmp, p1) + tA[pp4k[isp + 0] ^ 1];
		state[13] = state[9];
		state[9] = state[5];
		state[5] = tA[1];
		tmp = state[14] + w[2]
			+ (((state[6] ^ state[10]) & state[2]) ^ state[10]);
		state[2] = circularLeft(tmp, p1) + tA[pp4k[isp + 0] ^ 2];
		state[14] = state[10];
		state[10] = state[6];
		state[6] = tA[2];
		tmp = state[15] + w[3]
			+ (((state[7] ^ state[11]) & state[3]) ^ state[11]);
		state[3] = circularLeft(tmp, p1) + tA[pp4k[isp + 0] ^ 3];
		state[15] = state[11];
		state[11] = state[7];
		state[7] = tA[3];
		tA[0] = circularLeft(state[0], p1);
		tA[1] = circularLeft(state[1], p1);
		tA[2] = circularLeft(state[2], p1);
		tA[3] = circularLeft(state[3], p1);
		tmp = state[12] + w[4]
			+ (((state[4] ^ state[8]) & state[0]) ^ state[8]);
		state[0] = circularLeft(tmp, p2) + tA[pp4k[isp + 1] ^ 0];
		state[12] = state[8];
		state[8] = state[4];
		state[4] = tA[0];
		tmp = state[13] + w[5]
			+ (((state[5] ^ state[9]) & state[1]) ^ state[9]);
		state[1] = circularLeft(tmp, p2) + tA[pp4k[isp + 1] ^ 1];
		state[13] = state[9];
		state[9] = state[5];
		state[5] = tA[1];
		tmp = state[14] + w[6]
			+ (((state[6] ^ state[10]) & state[2]) ^ state[10]);
		state[2] = circularLeft(tmp, p2) + tA[pp4k[isp + 1] ^ 2];
		state[14] = state[10];
		state[10] = state[6];
		state[6] = tA[2];
		tmp = state[15] + w[7]
			+ (((state[7] ^ state[11]) & state[3]) ^ state[11]);
		state[3] = circularLeft(tmp, p2) + tA[pp4k[isp + 1] ^ 3];
		state[15] = state[11];
		state[11] = state[7];
		state[7] = tA[3];
		tA[0] = circularLeft(state[0], p2);
		tA[1] = circularLeft(state[1], p2);
		tA[2] = circularLeft(state[2], p2);
		tA[3] = circularLeft(state[3], p2);
		tmp = state[12] + w[8]
			+ (((state[4] ^ state[8]) & state[0]) ^ state[8]);
		state[0] = circularLeft(tmp, p3) + tA[pp4k[isp + 2] ^ 0];
		state[12] = state[8];
		state[8] = state[4];
		state[4] = tA[0];
		tmp = state[13] + w[9]
			+ (((state[5] ^ state[9]) & state[1]) ^ state[9]);
		state[1] = circularLeft(tmp, p3) + tA[pp4k[isp + 2] ^ 1];
		state[13] = state[9];
		state[9] = state[5];
		state[5] = tA[1];
		tmp = state[14] + w[10]
			+ (((state[6] ^ state[10]) & state[2]) ^ state[10]);
		state[2] = circularLeft(tmp, p3) + tA[pp4k[isp + 2] ^ 2];
		state[14] = state[10];
		state[10] = state[6];
		state[6] = tA[2];
		tmp = state[15] + w[11]
			+ (((state[7] ^ state[11]) & state[3]) ^ state[11]);
		state[3] = circularLeft(tmp, p3) + tA[pp4k[isp + 2] ^ 3];
		state[15] = state[11];
		state[11] = state[7];
		state[7] = tA[3];
		tA[0] = circularLeft(state[0], p3);
		tA[1] = circularLeft(state[1], p3);
		tA[2] = circularLeft(state[2], p3);
		tA[3] = circularLeft(state[3], p3);
		tmp = state[12] + w[12]
			+ (((state[4] ^ state[8]) & state[0]) ^ state[8]);
		state[0] = circularLeft(tmp, p0) + tA[pp4k[isp + 3] ^ 0];
		state[12] = state[8];
		state[8] = state[4];
		state[4] = tA[0];
		tmp = state[13] + w[13]
			+ (((state[5] ^ state[9]) & state[1]) ^ state[9]);
		state[1] = circularLeft(tmp, p0) + tA[pp4k[isp + 3] ^ 1];
		state[13] = state[9];
		state[9] = state[5];
		state[5] = tA[1];
		tmp = state[14] + w[14]
			+ (((state[6] ^ state[10]) & state[2]) ^ state[10]);
		state[2] = circularLeft(tmp, p0) + tA[pp4k[isp + 3] ^ 2];
		state[14] = state[10];
		state[10] = state[6];
		state[6] = tA[2];
		tmp = state[15] + w[15]
			+ (((state[7] ^ state[11]) & state[3]) ^ state[11]);
		state[3] = circularLeft(tmp, p0) + tA[pp4k[isp + 3] ^ 3];
		state[15] = state[11];
		state[11] = state[7];
		state[7] = tA[3];
		tA[0] = circularLeft(state[0], p0);
		tA[1] = circularLeft(state[1], p0);
		tA[2] = circularLeft(state[2], p0);
		tA[3] = circularLeft(state[3], p0);
		tmp = state[12] + w[16]
			+ ((state[0] & state[4])
			| ((state[0] | state[4]) & state[8]));
		state[0] = circularLeft(tmp, p1) + tA[pp4k[isp + 4] ^ 0];
		state[12] = state[8];
		state[8] = state[4];
		state[4] = tA[0];
		tmp = state[13] + w[17]
			+ ((state[1] & state[5])
			| ((state[1] | state[5]) & state[9]));
		state[1] = circularLeft(tmp, p1) + tA[pp4k[isp + 4] ^ 1];
		state[13] = state[9];
		state[9] = state[5];
		state[5] = tA[1];
		tmp = state[14] + w[18]
			+ ((state[2] & state[6])
			| ((state[2] | state[6]) & state[10]));
		state[2] = circularLeft(tmp, p1) + tA[pp4k[isp + 4] ^ 2];
		state[14] = state[10];
		state[10] = state[6];
		state[6] = tA[2];
		tmp = state[15] + w[19]
			+ ((state[3] & state[7])
			| ((state[3] | state[7]) & state[11]));
		state[3] = circularLeft(tmp, p1) + tA[pp4k[isp + 4] ^ 3];
		state[15] = state[11];
		state[11] = state[7];
		state[7] = tA[3];
		tA[0] = circularLeft(state[0], p1);
		tA[1] = circularLeft(state[1], p1);
		tA[2] = circularLeft(state[2], p1);
		tA[3] = circularLeft(state[3], p1);
		tmp = state[12] + w[20]
			+ ((state[0] & state[4])
			| ((state[0] | state[4]) & state[8]));
		state[0] = circularLeft(tmp, p2) + tA[pp4k[isp + 5] ^ 0];
		state[12] = state[8];
		state[8] = state[4];
		state[4] = tA[0];
		tmp = state[13] + w[21]
			+ ((state[1] & state[5])
			| ((state[1] | state[5]) & state[9]));
		state[1] = circularLeft(tmp, p2) + tA[pp4k[isp + 5] ^ 1];
		state[13] = state[9];
		state[9] = state[5];
		state[5] = tA[1];
		tmp = state[14] + w[22]
			+ ((state[2] & state[6])
			| ((state[2] | state[6]) & state[10]));
		state[2] = circularLeft(tmp, p2) + tA[pp4k[isp + 5] ^ 2];
		state[14] = state[10];
		state[10] = state[6];
		state[6] = tA[2];
		tmp = state[15] + w[23]
			+ ((state[3] & state[7])
			| ((state[3] | state[7]) & state[11]));
		state[3] = circularLeft(tmp, p2) + tA[pp4k[isp + 5] ^ 3];
		state[15] = state[11];
		state[11] = state[7];
		state[7] = tA[3];
		tA[0] = circularLeft(state[0], p2);
		tA[1] = circularLeft(state[1], p2);
		tA[2] = circularLeft(state[2], p2);
		tA[3] = circularLeft(state[3], p2);
		tmp = state[12] + w[24]
			+ ((state[0] & state[4])
			| ((state[0] | state[4]) & state[8]));
		state[0] = circularLeft(tmp, p3) + tA[pp4k[isp + 6] ^ 0];
		state[12] = state[8];
		state[8] = state[4];
		state[4] = tA[0];
		tmp = state[13] + w[25]
			+ ((state[1] & state[5])
			| ((state[1] | state[5]) & state[9]));
		state[1] = circularLeft(tmp, p3) + tA[pp4k[isp + 6] ^ 1];
		state[13] = state[9];
		state[9] = state[5];
		state[5] = tA[1];
		tmp = state[14] + w[26]
			+ ((state[2] & state[6])
			| ((state[2] | state[6]) & state[10]));
		state[2] = circularLeft(tmp, p3) + tA[pp4k[isp + 6] ^ 2];
		state[14] = state[10];
		state[10] = state[6];
		state[6] = tA[2];
		tmp = state[15] + w[27]
			+ ((state[3] & state[7])
			| ((state[3] | state[7]) & state[11]));
		state[3] = circularLeft(tmp, p3) + tA[pp4k[isp + 6] ^ 3];
		state[15] = state[11];
		state[11] = state[7];
		state[7] = tA[3];
		tA[0] = circularLeft(state[0], p3);
		tA[1] = circularLeft(state[1], p3);
		tA[2] = circularLeft(state[2], p3);
		tA[3] = circularLeft(state[3], p3);
		tmp = state[12] + w[28]
			+ ((state[0] & state[4])
			| ((state[0] | state[4]) & state[8]));
		state[0] = circularLeft(tmp, p0) + tA[pp4k[isp + 7] ^ 0];
		state[12] = state[8];
		state[8] = state[4];
		state[4] = tA[0];
		tmp = state[13] + w[29]
			+ ((state[1] & state[5])
			| ((state[1] | state[5]) & state[9]));
		state[1] = circularLeft(tmp, p0) + tA[pp4k[isp + 7] ^ 1];
		state[13] = state[9];
		state[9] = state[5];
		state[5] = tA[1];
		tmp = state[14] + w[30]
			+ ((state[2] & state[6])
			| ((state[2] | state[6]) & state[10]));
		state[2] = circularLeft(tmp, p0) + tA[pp4k[isp + 7] ^ 2];
		state[14] = state[10];
		state[10] = state[6];
		state[6] = tA[2];
		tmp = state[15] + w[31]
			+ ((state[3] & state[7])
			| ((state[3] | state[7]) & state[11]));
		state[3] = circularLeft(tmp, p0) + tA[pp4k[isp + 7] ^ 3];
		state[15] = state[11];
		state[11] = state[7];
		state[7] = tA[3];
	}

	private final void compress(byte[] x, boolean last)
	{
		fft32(x, 0 + (1 * 0), 1 << 2, 0 + 0);
		fft32(x, 0 + (1 * 2), 1 << 2, 0 + 32);
		int m = q[0];
		int n = q[0 + 32];
		q[0] = m + n;
		q[0 + 32] = m - n;
		for (int u = 0, v = 0; u < 32; u += 4, v += 4 * 4) {
			int t;
			if (u != 0) {
				m = q[0 + u + 0];
				n = q[0 + u + 0 + 32];
				t = (((n * alphaTab[v + 0 * 4]) & 0xFFFF)
					+ ((n * alphaTab[v + 0 * 4]) >> 16));
				q[0 + u + 0] = m + t;
				q[0 + u + 0 + 32] = m - t;
			}
			m = q[0 + u + 1];
			n = q[0 + u + 1 + 32];
			t = (((n * alphaTab[v + 1 * 4]) & 0xFFFF)
				+ ((n * alphaTab[v + 1 * 4]) >> 16));
			q[0 + u + 1] = m + t;
			q[0 + u + 1 + 32] = m - t;
			m = q[0 + u + 2];
			n = q[0 + u + 2 + 32];
			t = (((n * alphaTab[v + 2 * 4]) & 0xFFFF)
				+ ((n * alphaTab[v + 2 * 4]) >> 16));
			q[0 + u + 2] = m + t;
			q[0 + u + 2 + 32] = m - t;
			m = q[0 + u + 3];
			n = q[0 + u + 3 + 32];
			t = (((n * alphaTab[v + 3 * 4]) & 0xFFFF)
				+ ((n * alphaTab[v + 3 * 4]) >> 16));
			q[0 + u + 3] = m + t;
			q[0 + u + 3 + 32] = m - t;
		}
		fft32(x, 0 + (1 * 1), 1 << 2, 0 + 64);
		fft32(x, 0 + (1 * 3), 1 << 2, 0 + 96);
		m = q[(0 + 64)];
		n = q[(0 + 64) + 32];
		q[(0 + 64)] = m + n;
		q[(0 + 64) + 32] = m - n;
		for (int u = 0, v = 0; u < 32; u += 4, v += 4 * 4) {
			int t;
			if (u != 0) {
				m = q[(0 + 64) + u + 0];
				n = q[(0 + 64) + u + 0 + 32];
				t = (((n * alphaTab[v + 0 * 4]) & 0xFFFF)
					+ ((n * alphaTab[v + 0 * 4]) >> 16));
				q[(0 + 64) + u + 0] = m + t;
				q[(0 + 64) + u + 0 + 32] = m - t;
			}
			m = q[(0 + 64) + u + 1];
			n = q[(0 + 64) + u + 1 + 32];
			t = (((n * alphaTab[v + 1 * 4]) & 0xFFFF)
				+ ((n * alphaTab[v + 1 * 4]) >> 16));
			q[(0 + 64) + u + 1] = m + t;
			q[(0 + 64) + u + 1 + 32] = m - t;
			m = q[(0 + 64) + u + 2];
			n = q[(0 + 64) + u + 2 + 32];
			t = (((n * alphaTab[v + 2 * 4]) & 0xFFFF)
				+ ((n * alphaTab[v + 2 * 4]) >> 16));
			q[(0 + 64) + u + 2] = m + t;
			q[(0 + 64) + u + 2 + 32] = m - t;
			m = q[(0 + 64) + u + 3];
			n = q[(0 + 64) + u + 3 + 32];
			t = (((n * alphaTab[v + 3 * 4]) & 0xFFFF)
				+ ((n * alphaTab[v + 3 * 4]) >> 16));
			q[(0 + 64) + u + 3] = m + t;
			q[(0 + 64) + u + 3 + 32] = m - t;
		}
		m = q[0];
		n = q[0 + 64];
		q[0] = m + n;
		q[0 + 64] = m - n;
		for (int u = 0, v = 0; u < 64; u += 4, v += 4 * 2) {
			int t;
			if (u != 0) {
				m = q[0 + u + 0];
				n = q[0 + u + 0 + 64];
				t = (((n * alphaTab[v + 0 * 2]) & 0xFFFF)
					+ ((n * alphaTab[v + 0 * 2]) >> 16));
				q[0 + u + 0] = m + t;
				q[0 + u + 0 + 64] = m - t;
			}
			m = q[0 + u + 1];
			n = q[0 + u + 1 + 64];
			t = (((n * alphaTab[v + 1 * 2]) & 0xFFFF)
				+ ((n * alphaTab[v + 1 * 2]) >> 16));
			q[0 + u + 1] = m + t;
			q[0 + u + 1 + 64] = m - t;
			m = q[0 + u + 2];
			n = q[0 + u + 2 + 64];
			t = (((n * alphaTab[v + 2 * 2]) & 0xFFFF)
				+ ((n * alphaTab[v + 2 * 2]) >> 16));
			q[0 + u + 2] = m + t;
			q[0 + u + 2 + 64] = m - t;
			m = q[0 + u + 3];
			n = q[0 + u + 3 + 64];
			t = (((n * alphaTab[v + 3 * 2]) & 0xFFFF)
				+ ((n * alphaTab[v + 3 * 2]) >> 16));
			q[0 + u + 3] = m + t;
			q[0 + u + 3 + 64] = m - t;
		}
		if (last) {
			for (int i = 0; i < 128; i++) {
				int tq;

				tq = q[i] + yoffF[i];
				tq = ((tq & 0xFFFF) + (tq >> 16));
				tq = ((tq & 0xFF) - (tq >> 8));
				tq = ((tq & 0xFF) - (tq >> 8));
				q[i] = (tq <= 128 ? tq : tq - 257);
			}
		} else {
			for (int i = 0; i < 128; i++) {
				int tq;

				tq = q[i] + yoffN[i];
				tq = ((tq & 0xFFFF) + (tq >> 16));
				tq = ((tq & 0xFF) - (tq >> 8));
				tq = ((tq & 0xFF) - (tq >> 8));
				q[i] = (tq <= 128 ? tq : tq - 257);
			}
		}

		System.arraycopy(state, 0, tmpState, 0, 16);

		for (int i = 0; i < 16; i += 4) {
			state[i + 0] ^= decodeLEInt(x, 4 * (i + 0));
			state[i + 1] ^= decodeLEInt(x, 4 * (i + 1));
			state[i + 2] ^= decodeLEInt(x, 4 * (i + 2));
			state[i + 3] ^= decodeLEInt(x, 4 * (i + 3));
		}

		for (int u = 0; u < 32; u += 4) {
			int v = wsp[(u >> 2) + 0];
			w[u + 0] = ((((q[v + 2 * 0 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 0 + 1]) * 185) << 16));
			w[u + 1] = ((((q[v + 2 * 1 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 1 + 1]) * 185) << 16));
			w[u + 2] = ((((q[v + 2 * 2 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 2 + 1]) * 185) << 16));
			w[u + 3] = ((((q[v + 2 * 3 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 3 + 1]) * 185) << 16));
		};
		oneRound(0, 3, 23, 17, 27);
		for (int u = 0; u < 32; u += 4) {
			int v = wsp[(u >> 2) + 8];
			w[u + 0] = ((((q[v + 2 * 0 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 0 + 1]) * 185) << 16));
			w[u + 1] = ((((q[v + 2 * 1 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 1 + 1]) * 185) << 16));
			w[u + 2] = ((((q[v + 2 * 2 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 2 + 1]) * 185) << 16));
			w[u + 3] = ((((q[v + 2 * 3 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 3 + 1]) * 185) << 16));
		};
		oneRound(2, 28, 19, 22, 7);
		for (int u = 0; u < 32; u += 4) {
			int v = wsp[(u >> 2) + 16];
			w[u + 0] = ((((q[v + 2 * 0 + -128]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 0 + -64]) * 233) << 16));
			w[u + 1] = ((((q[v + 2 * 1 + -128]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 1 + -64]) * 233) << 16));
			w[u + 2] = ((((q[v + 2 * 2 + -128]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 2 + -64]) * 233) << 16));
			w[u + 3] = ((((q[v + 2 * 3 + -128]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 3 + -64]) * 233) << 16));
		};
		oneRound(1, 29, 9, 15, 5);
		for (int u = 0; u < 32; u += 4) {
			int v = wsp[(u >> 2) + 24];
			w[u + 0] = ((((q[v + 2 * 0 + -191]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 0 + -127]) * 233) << 16));
			w[u + 1] = ((((q[v + 2 * 1 + -191]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 1 + -127]) * 233) << 16));
			w[u + 2] = ((((q[v + 2 * 2 + -191]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 2 + -127]) * 233) << 16));
			w[u + 3] = ((((q[v + 2 * 3 + -191]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 3 + -127]) * 233) << 16));
		};
		oneRound(0, 4, 13, 10, 25);

		{
			int tA0 = circularLeft(state[0], 4);
			int tA1 = circularLeft(state[1], 4);
			int tA2 = circularLeft(state[2], 4);
			int tA3 = circularLeft(state[3], 4);
			int tmp;
			tmp = state[12] + (tmpState[0]) + (((state[4]
				^ state[8]) & state[0]) ^ state[8]);
			state[0] = circularLeft(tmp, 13) + tA3;
			state[12] = state[8];
			state[8] = state[4];
			state[4] = tA0;
			tmp = state[13] + (tmpState[1]) + (((state[5]
				^ state[9]) & state[1]) ^ state[9]);
			state[1] = circularLeft(tmp, 13) + tA2;
			state[13] = state[9];
			state[9] = state[5];
			state[5] = tA1;
			tmp = state[14] + (tmpState[2]) + (((state[6]
				^ state[10]) & state[2]) ^ state[10]);
			state[2] = circularLeft(tmp, 13) + tA1;
			state[14] = state[10];
			state[10] = state[6];
			state[6] = tA2;
			tmp = state[15] + (tmpState[3]) + (((state[7]
				^ state[11]) & state[3]) ^ state[11]);
			state[3] = circularLeft(tmp, 13) + tA0;
			state[15] = state[11];
			state[11] = state[7];
			state[7] = tA3;
		}
		{
			int tA0 = circularLeft(state[0], 13);
			int tA1 = circularLeft(state[1], 13);
			int tA2 = circularLeft(state[2], 13);
			int tA3 = circularLeft(state[3], 13);
			int tmp;
			tmp = state[12] + (tmpState[4]) + (((state[4]
				^ state[8]) & state[0]) ^ state[8]);
			state[0] = circularLeft(tmp, 10) + tA1;
			state[12] = state[8];
			state[8] = state[4];
			state[4] = tA0;
			tmp = state[13] + (tmpState[5]) + (((state[5]
				^ state[9]) & state[1]) ^ state[9]);
			state[1] = circularLeft(tmp, 10) + tA0;
			state[13] = state[9];
			state[9] = state[5];
			state[5] = tA1;
			tmp = state[14] + (tmpState[6]) + (((state[6]
				^ state[10]) & state[2]) ^ state[10]);
			state[2] = circularLeft(tmp, 10) + tA3;
			state[14] = state[10];
			state[10] = state[6];
			state[6] = tA2;
			tmp = state[15] + (tmpState[7]) + (((state[7]
				^ state[11]) & state[3]) ^ state[11]);
			state[3] = circularLeft(tmp, 10) + tA2;
			state[15] = state[11];
			state[11] = state[7];
			state[7] = tA3;
		}
		{
			int tA0 = circularLeft(state[0], 10);
			int tA1 = circularLeft(state[1], 10);
			int tA2 = circularLeft(state[2], 10);
			int tA3 = circularLeft(state[3], 10);
			int tmp;
			tmp = state[12] + (tmpState[8]) + (((state[4]
				^ state[8]) & state[0]) ^ state[8]);
			state[0] = circularLeft(tmp, 25) + tA2;
			state[12] = state[8];
			state[8] = state[4];
			state[4] = tA0;
			tmp = state[13] + (tmpState[9]) + (((state[5]
				^ state[9]) & state[1]) ^ state[9]);
			state[1] = circularLeft(tmp, 25) + tA3;
			state[13] = state[9];
			state[9] = state[5];
			state[5] = tA1;
			tmp = state[14] + (tmpState[10]) + (((state[6]
				^ state[10]) & state[2]) ^ state[10]);
			state[2] = circularLeft(tmp, 25) + tA0;
			state[14] = state[10];
			state[10] = state[6];
			state[6] = tA2;
			tmp = state[15] + (tmpState[11]) + (((state[7]
				^ state[11]) & state[3]) ^ state[11]);
			state[3] = circularLeft(tmp, 25) + tA1;
			state[15] = state[11];
			state[11] = state[7];
			state[7] = tA3;
		}
		{
			int tA0 = circularLeft(state[0], 25);
			int tA1 = circularLeft(state[1], 25);
			int tA2 = circularLeft(state[2], 25);
			int tA3 = circularLeft(state[3], 25);
			int tmp;
			tmp = state[12] + (tmpState[12]) + (((state[4]
				^ state[8]) & state[0]) ^ state[8]);
			state[0] = circularLeft(tmp, 4) + tA3;
			state[12] = state[8];
			state[8] = state[4];
			state[4] = tA0;
			tmp = state[13] + (tmpState[13]) + (((state[5]
				^ state[9]) & state[1]) ^ state[9]);
			state[1] = circularLeft(tmp, 4) + tA2;
			state[13] = state[9];
			state[9] = state[5];
			state[5] = tA1;
			tmp = state[14] + (tmpState[14]) + (((state[6]
				^ state[10]) & state[2]) ^ state[10]);
			state[2] = circularLeft(tmp, 4) + tA1;
			state[14] = state[10];
			state[10] = state[6];
			state[6] = tA2;
			tmp = state[15] + (tmpState[15]) + (((state[7]
				^ state[11]) & state[3]) ^ state[11]);
			state[3] = circularLeft(tmp, 4) + tA0;
			state[15] = state[11];
			state[11] = state[7];
			state[7] = tA3;
		}
	}

	/** @see Digest */
	public String toString()
	{
		return "SIMD-" + (getDigestLength() << 3);
	}
}
