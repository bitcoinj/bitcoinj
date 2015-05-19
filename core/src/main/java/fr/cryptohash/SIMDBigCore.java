// $Id: SIMDBigCore.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * This class implements SIMD-384 and SIMD-512.
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

abstract class SIMDBigCore extends DigestEngine {

	private int[] state;
	private int[] q, w, tmpState, tA;

	/**
	 * Create the object.
	 */
	SIMDBigCore()
	{
	}

	/** @see Digest */
	public int getBlockLength()
	{
		return 128;
	}

	/** @see DigestEngine */
	protected Digest copyState(SIMDBigCore dst)
	{
		System.arraycopy(state, 0, dst.state, 0, 32);
		return super.copyState(dst);
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		int[] iv = getInitVal();
		System.arraycopy(iv, 0, state, 0, 32);
	}

	/**
	 * Get the initial value for this algorithm.
	 *
	 * @return  the initial value
	 */
	abstract int[] getInitVal();

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		int ptr = flush();
		byte[] buf = getBlockBuffer();
		if (ptr != 0) {
			for (int i = ptr; i < 128; i ++)
				buf[i] = 0x00;
			compress(buf, false);
		}
		long count = (getBlockCount() << 10) + (long)(ptr << 3);
		encodeLEInt((int)count, buf, 0);
		encodeLEInt((int)(count >> 32), buf, 4);
		for (int i = 8; i < 128; i ++)
			buf[i] = 0x00;
		compress(buf, true);
		int n = getDigestLength() >>> 2;
		for (int i = 0; i < n; i ++)
			encodeLEInt(state[i], output, outputOffset + (i << 2));
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		state = new int[32];
		q = new int[256];
		w = new int[64];
		tmpState = new int[32];
		tA = new int[8];
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
		  1, 163,  98,  40,  95,  65,  58, 202,  30,   7, 113, 172,
		 23, 151, 198, 149, 129, 210,  49,  20, 176, 161,  29, 101,
		 15, 132, 185,  86, 140, 204,  99, 203, 193, 105, 153,  10,
		 88, 209, 143, 179, 136,  66, 221,  43,  70, 102, 178, 230,
		225, 181, 205,   5,  44, 233, 200, 218,  68,  33, 239, 150,
		 35,  51,  89, 115, 241, 219, 231, 131,  22, 245, 100, 109,
		 34, 145, 248,  75, 146, 154, 173, 186, 249, 238, 244, 194,
		 11, 251,  50, 183,  17, 201, 124, 166,  73,  77, 215,  93,
		253, 119, 122,  97, 134, 254,  25, 220, 137, 229,  62,  83,
		165, 167, 236, 175, 255, 188,  61, 177,  67, 127, 141, 110,
		197, 243,  31, 170, 211, 212, 118, 216, 256,  94, 159, 217,
		162, 192, 199,  55, 227, 250, 144,  85, 234, 106,  59, 108,
		128,  47, 208, 237,  81,  96, 228, 156, 242, 125,  72, 171,
		117,  53, 158,  54,  64, 152, 104, 247, 169,  48, 114,  78,
		121, 191,  36, 214, 187, 155,  79,  27,  32,  76,  52, 252,
		213,  24,  57,  39, 189, 224,  18, 107, 222, 206, 168, 142,
		 16,  38,  26, 126, 235,  12, 157, 148, 223, 112,   9, 182,
		111, 103,  84,  71,   8,  19,  13,  63, 246,   6, 207,  74,
		240,  56, 133,  91, 184, 180,  42, 164,   4, 138, 135, 160,
		123,   3, 232,  37, 120,  28, 195, 174,  92,  90,  21,  82,
		  2,  69, 196,  80, 190, 130, 116, 147,  60,  14, 226,  87,
		 46,  45, 139,  41
	};

	private static final int[] yoffF = {
		  2, 203, 156,  47, 118, 214, 107, 106,  45,  93, 212,  20,
		111,  73, 162, 251,  97, 215, 249,  53, 211,  19,   3,  89,
		 49, 207, 101,  67, 151, 130, 223,  23, 189, 202, 178, 239,
		253, 127, 204,  49,  76, 236,  82, 137, 232, 157,  65,  79,
		 96, 161, 176, 130, 161,  30,  47,   9, 189, 247,  61, 226,
		248,  90, 107,  64,   0,  88, 131, 243, 133,  59, 113, 115,
		 17, 236,  33, 213,  12, 191, 111,  19, 251,  61, 103, 208,
		 57,  35, 148, 248,  47, 116,  65, 119, 249, 178, 143,  40,
		189, 129,   8, 163, 204, 227, 230, 196, 205, 122, 151,  45,
		187,  19, 227,  72, 247, 125, 111, 121, 140, 220,   6, 107,
		 77,  69,  10, 101,  21,  65, 149, 171, 255,  54, 101, 210,
		139,  43, 150, 151, 212, 164,  45, 237, 146, 184,  95,   6,
		160,  42,   8, 204,  46, 238, 254, 168, 208,  50, 156, 190,
		106, 127,  34, 234,  68,  55,  79,  18,   4, 130,  53, 208,
		181,  21, 175, 120,  25, 100, 192, 178, 161,  96,  81, 127,
		 96, 227, 210, 248,  68,  10, 196,  31,   9, 167, 150, 193,
		  0, 169, 126,  14, 124, 198, 144, 142, 240,  21, 224,  44,
		245,  66, 146, 238,   6, 196, 154,  49, 200, 222, 109,   9,
		210, 141, 192, 138,   8,  79, 114, 217,  68, 128, 249,  94,
		 53,  30,  27,  61,  52, 135, 106, 212,  70, 238,  30, 185,
		 10, 132, 146, 136, 117,  37, 251, 150, 180, 188, 247, 156,
		236, 192, 108,  86
	};

	private final void fft64(byte[] x, int xb, int xs, int qoff)
	{
		int xd = xs << 1;
		{
			int d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7;
			int d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7;
			{
				int x0 = x[xb +  0 * xd] & 0xFF;
				int x1 = x[xb +  4 * xd] & 0xFF;
				int x2 = x[xb +  8 * xd] & 0xFF;
				int x3 = x[xb + 12 * xd] & 0xFF;
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
				int x0 = x[xb +  2 * xd] & 0xFF;
				int x1 = x[xb +  6 * xd] & 0xFF;
				int x2 = x[xb + 10 * xd] & 0xFF;
				int x3 = x[xb + 14 * xd] & 0xFF;
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
				int x0 = x[xb +  1 * xd] & 0xFF;
				int x1 = x[xb +  5 * xd] & 0xFF;
				int x2 = x[xb +  9 * xd] & 0xFF;
				int x3 = x[xb + 13 * xd] & 0xFF;
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
				int x0 = x[xb +  3 * xd] & 0xFF;
				int x1 = x[xb +  7 * xd] & 0xFF;
				int x2 = x[xb + 11 * xd] & 0xFF;
				int x3 = x[xb + 15 * xd] & 0xFF;
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
			t = ((n * alphaTab[v + 1 * 8]) & 0xFFFF)
				+ ((n * alphaTab[v + 1 * 8]) >> 16);
			q[qoff + u + 1] = m + t;
			q[qoff + u + 1 + 16] = m - t;
			m = q[qoff + u + 2];
			n = q[qoff + u + 2 + 16];
			t = ((n * alphaTab[v + 2 * 8]) & 0xFFFF)
				+ ((n * alphaTab[v + 2 * 8]) >> 16);
			q[qoff + u + 2] = m + t;
			q[qoff + u + 2 + 16] = m - t;
			m = q[qoff + u + 3];
			n = q[qoff + u + 3 + 16];
			t = ((n * alphaTab[v + 3 * 8]) & 0xFFFF)
				+ ((n * alphaTab[v + 3 * 8]) >> 16);
			q[qoff + u + 3] = m + t;
			q[qoff + u + 3 + 16] = m - t;
		}
		{
			int d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7;
			int d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7;
			{
				int x0 = x[xb + xs +  0 * xd] & 0xFF;
				int x1 = x[xb + xs +  4 * xd] & 0xFF;
				int x2 = x[xb + xs +  8 * xd] & 0xFF;
				int x3 = x[xb + xs + 12 * xd] & 0xFF;
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
				int x0 = x[xb + xs +  2 * xd] & 0xFF;
				int x1 = x[xb + xs +  6 * xd] & 0xFF;
				int x2 = x[xb + xs + 10 * xd] & 0xFF;
				int x3 = x[xb + xs + 14 * xd] & 0xFF;
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
			q[qoff + 32 +  0] = d1_0 + d2_0;
			q[qoff + 32 +  1] = d1_1 + (d2_1 << 1);
			q[qoff + 32 +  2] = d1_2 + (d2_2 << 2);
			q[qoff + 32 +  3] = d1_3 + (d2_3 << 3);
			q[qoff + 32 +  4] = d1_4 + (d2_4 << 4);
			q[qoff + 32 +  5] = d1_5 + (d2_5 << 5);
			q[qoff + 32 +  6] = d1_6 + (d2_6 << 6);
			q[qoff + 32 +  7] = d1_7 + (d2_7 << 7);
			q[qoff + 32 +  8] = d1_0 - d2_0;
			q[qoff + 32 +  9] = d1_1 - (d2_1 << 1);
			q[qoff + 32 + 10] = d1_2 - (d2_2 << 2);
			q[qoff + 32 + 11] = d1_3 - (d2_3 << 3);
			q[qoff + 32 + 12] = d1_4 - (d2_4 << 4);
			q[qoff + 32 + 13] = d1_5 - (d2_5 << 5);
			q[qoff + 32 + 14] = d1_6 - (d2_6 << 6);
			q[qoff + 32 + 15] = d1_7 - (d2_7 << 7);
		}
		{
			int d1_0, d1_1, d1_2, d1_3, d1_4, d1_5, d1_6, d1_7;
			int d2_0, d2_1, d2_2, d2_3, d2_4, d2_5, d2_6, d2_7;
			{
				int x0 = x[xb + xs +  1 * xd] & 0xFF;
				int x1 = x[xb + xs +  5 * xd] & 0xFF;
				int x2 = x[xb + xs +  9 * xd] & 0xFF;
				int x3 = x[xb + xs + 13 * xd] & 0xFF;
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
				int x0 = x[xb + xs +  3 * xd] & 0xFF;
				int x1 = x[xb + xs +  7 * xd] & 0xFF;
				int x2 = x[xb + xs + 11 * xd] & 0xFF;
				int x3 = x[xb + xs + 15 * xd] & 0xFF;
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
			q[qoff + 32 + 16 +  0] = d1_0 + d2_0;
			q[qoff + 32 + 16 +  1] = d1_1 + (d2_1 << 1);
			q[qoff + 32 + 16 +  2] = d1_2 + (d2_2 << 2);
			q[qoff + 32 + 16 +  3] = d1_3 + (d2_3 << 3);
			q[qoff + 32 + 16 +  4] = d1_4 + (d2_4 << 4);
			q[qoff + 32 + 16 +  5] = d1_5 + (d2_5 << 5);
			q[qoff + 32 + 16 +  6] = d1_6 + (d2_6 << 6);
			q[qoff + 32 + 16 +  7] = d1_7 + (d2_7 << 7);
			q[qoff + 32 + 16 +  8] = d1_0 - d2_0;
			q[qoff + 32 + 16 +  9] = d1_1 - (d2_1 << 1);
			q[qoff + 32 + 16 + 10] = d1_2 - (d2_2 << 2);
			q[qoff + 32 + 16 + 11] = d1_3 - (d2_3 << 3);
			q[qoff + 32 + 16 + 12] = d1_4 - (d2_4 << 4);
			q[qoff + 32 + 16 + 13] = d1_5 - (d2_5 << 5);
			q[qoff + 32 + 16 + 14] = d1_6 - (d2_6 << 6);
			q[qoff + 32 + 16 + 15] = d1_7 - (d2_7 << 7);
		}
		m = q[qoff + 32];
		n = q[qoff + 32 + 16];
		q[qoff + 32] = m + n;
		q[qoff + 32 + 16] = m - n;
		for (int u = 0, v = 0; u < 16; u += 4, v += 4 * 8) {
			int t;
			if (u != 0) {
				m = q[(qoff + 32) + u + 0];
				n = q[(qoff + 32) + u + 0 + 16];
				t = ((n * alphaTab[v + 0 * 8]) & 0xFFFF)
					+ ((n * alphaTab[v + 0 * 8]) >> 16);
				q[(qoff + 32) + u + 0] = m + t;
				q[(qoff + 32) + u + 0 + 16] = m - t;
			}
			m = q[(qoff + 32) + u + 1];
			n = q[(qoff + 32) + u + 1 + 16];
			t = ((n * alphaTab[v + 1 * 8]) & 0xFFFF)
				+ ((n * alphaTab[v + 1 * 8]) >> 16);
			q[(qoff + 32) + u + 1] = m + t;
			q[(qoff + 32) + u + 1 + 16] = m - t;
			m = q[(qoff + 32) + u + 2];
			n = q[(qoff + 32) + u + 2 + 16];
			t = ((n * alphaTab[v + 2 * 8]) & 0xFFFF)
				+ ((n * alphaTab[v + 2 * 8]) >> 16);
			q[(qoff + 32) + u + 2] = m + t;
			q[(qoff + 32) + u + 2 + 16] = m - t;
			m = q[(qoff + 32) + u + 3];
			n = q[(qoff + 32) + u + 3 + 16];
			t = ((n * alphaTab[v + 3 * 8]) & 0xFFFF)
				+ ((n * alphaTab[v + 3 * 8]) >> 16);
			q[(qoff + 32) + u + 3] = m + t;
			q[(qoff + 32) + u + 3 + 16] = m - t;
		}
		m = q[qoff];
		n = q[qoff + 32];
		q[qoff] = m + n;
		q[qoff + 32] = m - n;
		for (int u = 0, v = 0; u < 32; u += 4, v += 4 * 4) {
			int t;
			if (u != 0) {
				m = q[qoff + u + 0];
				n = q[qoff + u + 0 + 32];
				t = ((n * alphaTab[v + 0 * 4]) & 0xFFFF)
					+ ((n * alphaTab[v + 0 * 4]) >> 16);
				q[qoff + u + 0] = m + t;
				q[qoff + u + 0 + 32] = m - t;
			}
			m = q[qoff + u + 1];
			n = q[qoff + u + 1 + 32];
			t = ((n * alphaTab[v + 1 * 4]) & 0xFFFF)
				+ ((n * alphaTab[v + 1 * 4]) >> 16);
			q[qoff + u + 1] = m + t;
			q[qoff + u + 1 + 32] = m - t;
			m = q[qoff + u + 2];
			n = q[qoff + u + 2 + 32];
			t = ((n * alphaTab[v + 2 * 4]) & 0xFFFF)
				+ ((n * alphaTab[v + 2 * 4]) >> 16);
			q[qoff + u + 2] = m + t;
			q[qoff + u + 2 + 32] = m - t;
			m = q[qoff + u + 3];
			n = q[qoff + u + 3 + 32];
			t = ((n * alphaTab[v + 3 * 4]) & 0xFFFF)
				+ ((n * alphaTab[v + 3 * 4]) >> 16);
			q[qoff + u + 3] = m + t;
			q[qoff + u + 3 + 32] = m - t;
		}
	}

	private static final int[] pp8k = {
		1, 6, 2, 3, 5, 7, 4, 1, 6, 2, 3
	};

	private static final int[] wbp = {
		 4 << 4,  6 << 4,  0 << 4,  2 << 4,
		 7 << 4,  5 << 4,  3 << 4,  1 << 4,
		15 << 4, 11 << 4, 12 << 4,  8 << 4,
		 9 << 4, 13 << 4, 10 << 4, 14 << 4,
		17 << 4, 18 << 4, 23 << 4, 20 << 4,
		22 << 4, 21 << 4, 16 << 4, 19 << 4,
		30 << 4, 24 << 4, 25 << 4, 31 << 4,
		27 << 4, 29 << 4, 28 << 4, 26 << 4
	};

	private final void oneRound(int isp, int p0, int p1, int p2, int p3)
	{
		int tmp;
		tA[0] = circularLeft(state[0], p0);
		tA[1] = circularLeft(state[1], p0);
		tA[2] = circularLeft(state[2], p0);
		tA[3] = circularLeft(state[3], p0);
		tA[4] = circularLeft(state[4], p0);
		tA[5] = circularLeft(state[5], p0);
		tA[6] = circularLeft(state[6], p0);
		tA[7] = circularLeft(state[7], p0);
		tmp = state[24] + (w[0])
			+ (((state[8] ^ state[16]) & state[0]) ^ state[16]);
		state[0] = circularLeft(tmp, p1) + tA[(pp8k[isp + 0]) ^ 0];
		state[24] = state[16];
		state[16] = state[8];
		state[8] = tA[0];
		tmp = state[25] + (w[1])
			+ (((state[9] ^ state[17]) & state[1]) ^ state[17]);
		state[1] = circularLeft(tmp, p1) + tA[(pp8k[isp + 0]) ^ 1];
		state[25] = state[17];
		state[17] = state[9];
		state[9] = tA[1];
		tmp = state[26] + (w[2])
			+ (((state[10] ^ state[18]) & state[2]) ^ state[18]);
		state[2] = circularLeft(tmp, p1) + tA[(pp8k[isp + 0]) ^ 2];
		state[26] = state[18];
		state[18] = state[10];
		state[10] = tA[2];
		tmp = state[27] + (w[3])
			+ (((state[11] ^ state[19]) & state[3]) ^ state[19]);
		state[3] = circularLeft(tmp, p1) + tA[(pp8k[isp + 0]) ^ 3];
		state[27] = state[19];
		state[19] = state[11];
		state[11] = tA[3];
		tmp = state[28] + (w[4])
			+ (((state[12] ^ state[20]) & state[4]) ^ state[20]);
		state[4] = circularLeft(tmp, p1) + tA[(pp8k[isp + 0]) ^ 4];
		state[28] = state[20];
		state[20] = state[12];
		state[12] = tA[4];
		tmp = state[29] + (w[5])
			+ (((state[13] ^ state[21]) & state[5]) ^ state[21]);
		state[5] = circularLeft(tmp, p1) + tA[(pp8k[isp + 0]) ^ 5];
		state[29] = state[21];
		state[21] = state[13];
		state[13] = tA[5];
		tmp = state[30] + (w[6])
			+ (((state[14] ^ state[22]) & state[6]) ^ state[22]);
		state[6] = circularLeft(tmp, p1) + tA[(pp8k[isp + 0]) ^ 6];
		state[30] = state[22];
		state[22] = state[14];
		state[14] = tA[6];
		tmp = state[31] + (w[7])
			+ (((state[15] ^ state[23]) & state[7]) ^ state[23]);
		state[7] = circularLeft(tmp, p1) + tA[(pp8k[isp + 0]) ^ 7];
		state[31] = state[23];
		state[23] = state[15];
		state[15] = tA[7];

		tA[0] = circularLeft(state[0], p1);
		tA[1] = circularLeft(state[1], p1);
		tA[2] = circularLeft(state[2], p1);
		tA[3] = circularLeft(state[3], p1);
		tA[4] = circularLeft(state[4], p1);
		tA[5] = circularLeft(state[5], p1);
		tA[6] = circularLeft(state[6], p1);
		tA[7] = circularLeft(state[7], p1);
		tmp = state[24] + (w[8])
			+ (((state[8] ^ state[16]) & state[0]) ^ state[16]);
		state[0] = circularLeft(tmp, p2) + tA[(pp8k[isp + 1]) ^ 0];
		state[24] = state[16];
		state[16] = state[8];
		state[8] = tA[0];
		tmp = state[25] + (w[9])
			+ (((state[9] ^ state[17]) & state[1]) ^ state[17]);
		state[1] = circularLeft(tmp, p2) + tA[(pp8k[isp + 1]) ^ 1];
		state[25] = state[17];
		state[17] = state[9];
		state[9] = tA[1];
		tmp = state[26] + (w[10])
			+ (((state[10] ^ state[18]) & state[2]) ^ state[18]);
		state[2] = circularLeft(tmp, p2) + tA[(pp8k[isp + 1]) ^ 2];
		state[26] = state[18];
		state[18] = state[10];
		state[10] = tA[2];
		tmp = state[27] + (w[11])
			+ (((state[11] ^ state[19]) & state[3]) ^ state[19]);
		state[3] = circularLeft(tmp, p2) + tA[(pp8k[isp + 1]) ^ 3];
		state[27] = state[19];
		state[19] = state[11];
		state[11] = tA[3];
		tmp = state[28] + (w[12])
			+ (((state[12] ^ state[20]) & state[4]) ^ state[20]);
		state[4] = circularLeft(tmp, p2) + tA[(pp8k[isp + 1]) ^ 4];
		state[28] = state[20];
		state[20] = state[12];
		state[12] = tA[4];
		tmp = state[29] + (w[13])
			+ (((state[13] ^ state[21]) & state[5]) ^ state[21]);
		state[5] = circularLeft(tmp, p2) + tA[(pp8k[isp + 1]) ^ 5];
		state[29] = state[21];
		state[21] = state[13];
		state[13] = tA[5];
		tmp = state[30] + (w[14])
			+ (((state[14] ^ state[22]) & state[6]) ^ state[22]);
		state[6] = circularLeft(tmp, p2) + tA[(pp8k[isp + 1]) ^ 6];
		state[30] = state[22];
		state[22] = state[14];
		state[14] = tA[6];
		tmp = state[31] + (w[15])
			+ (((state[15] ^ state[23]) & state[7]) ^ state[23]);
		state[7] = circularLeft(tmp, p2) + tA[(pp8k[isp + 1]) ^ 7];
		state[31] = state[23];
		state[23] = state[15];
		state[15] = tA[7];

		tA[0] = circularLeft(state[0], p2);
		tA[1] = circularLeft(state[1], p2);
		tA[2] = circularLeft(state[2], p2);
		tA[3] = circularLeft(state[3], p2);
		tA[4] = circularLeft(state[4], p2);
		tA[5] = circularLeft(state[5], p2);
		tA[6] = circularLeft(state[6], p2);
		tA[7] = circularLeft(state[7], p2);
		tmp = state[24] + (w[16])
			+ (((state[8] ^ state[16]) & state[0]) ^ state[16]);
		state[0] = circularLeft(tmp, p3) + tA[(pp8k[isp + 2]) ^ 0];
		state[24] = state[16];
		state[16] = state[8];
		state[8] = tA[0];
		tmp = state[25] + (w[17])
			+ (((state[9] ^ state[17]) & state[1]) ^ state[17]);
		state[1] = circularLeft(tmp, p3) + tA[(pp8k[isp + 2]) ^ 1];
		state[25] = state[17];
		state[17] = state[9];
		state[9] = tA[1];
		tmp = state[26] + (w[18])
			+ (((state[10] ^ state[18]) & state[2]) ^ state[18]);
		state[2] = circularLeft(tmp, p3) + tA[(pp8k[isp + 2]) ^ 2];
		state[26] = state[18];
		state[18] = state[10];
		state[10] = tA[2];
		tmp = state[27] + (w[19])
			+ (((state[11] ^ state[19]) & state[3]) ^ state[19]);
		state[3] = circularLeft(tmp, p3) + tA[(pp8k[isp + 2]) ^ 3];
		state[27] = state[19];
		state[19] = state[11];
		state[11] = tA[3];
		tmp = state[28] + (w[20])
			+ (((state[12] ^ state[20]) & state[4]) ^ state[20]);
		state[4] = circularLeft(tmp, p3) + tA[(pp8k[isp + 2]) ^ 4];
		state[28] = state[20];
		state[20] = state[12];
		state[12] = tA[4];
		tmp = state[29] + (w[21])
			+ (((state[13] ^ state[21]) & state[5]) ^ state[21]);
		state[5] = circularLeft(tmp, p3) + tA[(pp8k[isp + 2]) ^ 5];
		state[29] = state[21];
		state[21] = state[13];
		state[13] = tA[5];
		tmp = state[30] + (w[22])
			+ (((state[14] ^ state[22]) & state[6]) ^ state[22]);
		state[6] = circularLeft(tmp, p3) + tA[(pp8k[isp + 2]) ^ 6];
		state[30] = state[22];
		state[22] = state[14];
		state[14] = tA[6];
		tmp = state[31] + (w[23])
			+ (((state[15] ^ state[23]) & state[7]) ^ state[23]);
		state[7] = circularLeft(tmp, p3) + tA[(pp8k[isp + 2]) ^ 7];
		state[31] = state[23];
		state[23] = state[15];
		state[15] = tA[7];

		tA[0] = circularLeft(state[0], p3);
		tA[1] = circularLeft(state[1], p3);
		tA[2] = circularLeft(state[2], p3);
		tA[3] = circularLeft(state[3], p3);
		tA[4] = circularLeft(state[4], p3);
		tA[5] = circularLeft(state[5], p3);
		tA[6] = circularLeft(state[6], p3);
		tA[7] = circularLeft(state[7], p3);
		tmp = state[24] + (w[24])
			+ (((state[8] ^ state[16]) & state[0]) ^ state[16]);
		state[0] = circularLeft(tmp, p0) + tA[(pp8k[isp + 3]) ^ 0];
		state[24] = state[16];
		state[16] = state[8];
		state[8] = tA[0];
		tmp = state[25] + (w[25])
			+ (((state[9] ^ state[17]) & state[1]) ^ state[17]);
		state[1] = circularLeft(tmp, p0) + tA[(pp8k[isp + 3]) ^ 1];
		state[25] = state[17];
		state[17] = state[9];
		state[9] = tA[1];
		tmp = state[26] + (w[26])
			+ (((state[10] ^ state[18]) & state[2]) ^ state[18]);
		state[2] = circularLeft(tmp, p0) + tA[(pp8k[isp + 3]) ^ 2];
		state[26] = state[18];
		state[18] = state[10];
		state[10] = tA[2];
		tmp = state[27] + (w[27])
			+ (((state[11] ^ state[19]) & state[3]) ^ state[19]);
		state[3] = circularLeft(tmp, p0) + tA[(pp8k[isp + 3]) ^ 3];
		state[27] = state[19];
		state[19] = state[11];
		state[11] = tA[3];
		tmp = state[28] + (w[28])
			+ (((state[12] ^ state[20]) & state[4]) ^ state[20]);
		state[4] = circularLeft(tmp, p0) + tA[(pp8k[isp + 3]) ^ 4];
		state[28] = state[20];
		state[20] = state[12];
		state[12] = tA[4];
		tmp = state[29] + (w[29])
			+ (((state[13] ^ state[21]) & state[5]) ^ state[21]);
		state[5] = circularLeft(tmp, p0) + tA[(pp8k[isp + 3]) ^ 5];
		state[29] = state[21];
		state[21] = state[13];
		state[13] = tA[5];
		tmp = state[30] + (w[30])
			+ (((state[14] ^ state[22]) & state[6]) ^ state[22]);
		state[6] = circularLeft(tmp, p0) + tA[(pp8k[isp + 3]) ^ 6];
		state[30] = state[22];
		state[22] = state[14];
		state[14] = tA[6];
		tmp = state[31] + (w[31])
			+ (((state[15] ^ state[23]) & state[7]) ^ state[23]);
		state[7] = circularLeft(tmp, p0) + tA[(pp8k[isp + 3]) ^ 7];
		state[31] = state[23];
		state[23] = state[15];
		state[15] = tA[7];

		tA[0] = circularLeft(state[0], p0);
		tA[1] = circularLeft(state[1], p0);
		tA[2] = circularLeft(state[2], p0);
		tA[3] = circularLeft(state[3], p0);
		tA[4] = circularLeft(state[4], p0);
		tA[5] = circularLeft(state[5], p0);
		tA[6] = circularLeft(state[6], p0);
		tA[7] = circularLeft(state[7], p0);
		tmp = state[24] + (w[32])
			+ ((state[0] & state[8])
			| ((state[0] | state[8]) & state[16]));
		state[0] = circularLeft(tmp, p1) + tA[(pp8k[isp + 4]) ^ 0];
		state[24] = state[16];
		state[16] = state[8];
		state[8] = tA[0];
		tmp = state[25] + (w[33])
			+ ((state[1] & state[9])
			| ((state[1] | state[9]) & state[17]));
		state[1] = circularLeft(tmp, p1) + tA[(pp8k[isp + 4]) ^ 1];
		state[25] = state[17];
		state[17] = state[9];
		state[9] = tA[1];
		tmp = state[26] + (w[34])
			+ ((state[2] & state[10])
			| ((state[2] | state[10]) & state[18]));
		state[2] = circularLeft(tmp, p1) + tA[(pp8k[isp + 4]) ^ 2];
		state[26] = state[18];
		state[18] = state[10];
		state[10] = tA[2];
		tmp = state[27] + (w[35])
			+ ((state[3] & state[11])
			| ((state[3] | state[11]) & state[19]));
		state[3] = circularLeft(tmp, p1) + tA[(pp8k[isp + 4]) ^ 3];
		state[27] = state[19];
		state[19] = state[11];
		state[11] = tA[3];
		tmp = state[28] + (w[36])
			+ ((state[4] & state[12])
			| ((state[4] | state[12]) & state[20]));
		state[4] = circularLeft(tmp, p1) + tA[(pp8k[isp + 4]) ^ 4];
		state[28] = state[20];
		state[20] = state[12];
		state[12] = tA[4];
		tmp = state[29] + (w[37])
			+ ((state[5] & state[13])
			| ((state[5] | state[13]) & state[21]));
		state[5] = circularLeft(tmp, p1) + tA[(pp8k[isp + 4]) ^ 5];
		state[29] = state[21];
		state[21] = state[13];
		state[13] = tA[5];
		tmp = state[30] + (w[38])
			+ ((state[6] & state[14])
			| ((state[6] | state[14]) & state[22]));
		state[6] = circularLeft(tmp, p1) + tA[(pp8k[isp + 4]) ^ 6];
		state[30] = state[22];
		state[22] = state[14];
		state[14] = tA[6];
		tmp = state[31] + (w[39])
			+ ((state[7] & state[15])
			| ((state[7] | state[15]) & state[23]));
		state[7] = circularLeft(tmp, p1) + tA[(pp8k[isp + 4]) ^ 7];
		state[31] = state[23];
		state[23] = state[15];
		state[15] = tA[7];

		tA[0] = circularLeft(state[0], p1);
		tA[1] = circularLeft(state[1], p1);
		tA[2] = circularLeft(state[2], p1);
		tA[3] = circularLeft(state[3], p1);
		tA[4] = circularLeft(state[4], p1);
		tA[5] = circularLeft(state[5], p1);
		tA[6] = circularLeft(state[6], p1);
		tA[7] = circularLeft(state[7], p1);
		tmp = state[24] + (w[40])
			+ ((state[0] & state[8])
			| ((state[0] | state[8]) & state[16]));
		state[0] = circularLeft(tmp, p2) + tA[(pp8k[isp + 5]) ^ 0];
		state[24] = state[16];
		state[16] = state[8];
		state[8] = tA[0];
		tmp = state[25] + (w[41])
			+ ((state[1] & state[9])
			| ((state[1] | state[9]) & state[17]));
		state[1] = circularLeft(tmp, p2) + tA[(pp8k[isp + 5]) ^ 1];
		state[25] = state[17];
		state[17] = state[9];
		state[9] = tA[1];
		tmp = state[26] + (w[42])
			+ ((state[2] & state[10])
			| ((state[2] | state[10]) & state[18]));
		state[2] = circularLeft(tmp, p2) + tA[(pp8k[isp + 5]) ^ 2];
		state[26] = state[18];
		state[18] = state[10];
		state[10] = tA[2];
		tmp = state[27] + (w[43])
			+ ((state[3] & state[11])
			| ((state[3] | state[11]) & state[19]));
		state[3] = circularLeft(tmp, p2) + tA[(pp8k[isp + 5]) ^ 3];
		state[27] = state[19];
		state[19] = state[11];
		state[11] = tA[3];
		tmp = state[28] + (w[44])
			+ ((state[4] & state[12])
			| ((state[4] | state[12]) & state[20]));
		state[4] = circularLeft(tmp, p2) + tA[(pp8k[isp + 5]) ^ 4];
		state[28] = state[20];
		state[20] = state[12];
		state[12] = tA[4];
		tmp = state[29] + (w[45])
			+ ((state[5] & state[13])
			| ((state[5] | state[13]) & state[21]));
		state[5] = circularLeft(tmp, p2) + tA[(pp8k[isp + 5]) ^ 5];
		state[29] = state[21];
		state[21] = state[13];
		state[13] = tA[5];
		tmp = state[30] + (w[46])
			+ ((state[6] & state[14])
			| ((state[6] | state[14]) & state[22]));
		state[6] = circularLeft(tmp, p2) + tA[(pp8k[isp + 5]) ^ 6];
		state[30] = state[22];
		state[22] = state[14];
		state[14] = tA[6];
		tmp = state[31] + (w[47])
			+ ((state[7] & state[15])
			| ((state[7] | state[15]) & state[23]));
		state[7] = circularLeft(tmp, p2) + tA[(pp8k[isp + 5]) ^ 7];
		state[31] = state[23];
		state[23] = state[15];
		state[15] = tA[7];

		tA[0] = circularLeft(state[0], p2);
		tA[1] = circularLeft(state[1], p2);
		tA[2] = circularLeft(state[2], p2);
		tA[3] = circularLeft(state[3], p2);
		tA[4] = circularLeft(state[4], p2);
		tA[5] = circularLeft(state[5], p2);
		tA[6] = circularLeft(state[6], p2);
		tA[7] = circularLeft(state[7], p2);
		tmp = state[24] + (w[48])
			+ ((state[0] & state[8])
			| ((state[0] | state[8]) & state[16]));
		state[0] = circularLeft(tmp, p3) + tA[(pp8k[isp + 6]) ^ 0];
		state[24] = state[16];
		state[16] = state[8];
		state[8] = tA[0];
		tmp = state[25] + (w[49])
			+ ((state[1] & state[9])
			| ((state[1] | state[9]) & state[17]));
		state[1] = circularLeft(tmp, p3) + tA[(pp8k[isp + 6]) ^ 1];
		state[25] = state[17];
		state[17] = state[9];
		state[9] = tA[1];
		tmp = state[26] + (w[50])
			+ ((state[2] & state[10])
			| ((state[2] | state[10]) & state[18]));
		state[2] = circularLeft(tmp, p3) + tA[(pp8k[isp + 6]) ^ 2];
		state[26] = state[18];
		state[18] = state[10];
		state[10] = tA[2];
		tmp = state[27] + (w[51])
			+ ((state[3] & state[11])
			| ((state[3] | state[11]) & state[19]));
		state[3] = circularLeft(tmp, p3) + tA[(pp8k[isp + 6]) ^ 3];
		state[27] = state[19];
		state[19] = state[11];
		state[11] = tA[3];
		tmp = state[28] + (w[52])
			+ ((state[4] & state[12])
			| ((state[4] | state[12]) & state[20]));
		state[4] = circularLeft(tmp, p3) + tA[(pp8k[isp + 6]) ^ 4];
		state[28] = state[20];
		state[20] = state[12];
		state[12] = tA[4];
		tmp = state[29] + (w[53])
			+ ((state[5] & state[13])
			| ((state[5] | state[13]) & state[21]));
		state[5] = circularLeft(tmp, p3) + tA[(pp8k[isp + 6]) ^ 5];
		state[29] = state[21];
		state[21] = state[13];
		state[13] = tA[5];
		tmp = state[30] + (w[54])
			+ ((state[6] & state[14])
			| ((state[6] | state[14]) & state[22]));
		state[6] = circularLeft(tmp, p3) + tA[(pp8k[isp + 6]) ^ 6];
		state[30] = state[22];
		state[22] = state[14];
		state[14] = tA[6];
		tmp = state[31] + (w[55])
			+ ((state[7] & state[15])
			| ((state[7] | state[15]) & state[23]));
		state[7] = circularLeft(tmp, p3) + tA[(pp8k[isp + 6]) ^ 7];
		state[31] = state[23];
		state[23] = state[15];
		state[15] = tA[7];

		tA[0] = circularLeft(state[0], p3);
		tA[1] = circularLeft(state[1], p3);
		tA[2] = circularLeft(state[2], p3);
		tA[3] = circularLeft(state[3], p3);
		tA[4] = circularLeft(state[4], p3);
		tA[5] = circularLeft(state[5], p3);
		tA[6] = circularLeft(state[6], p3);
		tA[7] = circularLeft(state[7], p3);
		tmp = state[24] + (w[56])
			+ ((state[0] & state[8])
			| ((state[0] | state[8]) & state[16]));
		state[0] = circularLeft(tmp, p0) + tA[(pp8k[isp + 7]) ^ 0];
		state[24] = state[16];
		state[16] = state[8];
		state[8] = tA[0];
		tmp = state[25] + (w[57])
			+ ((state[1] & state[9])
			| ((state[1] | state[9]) & state[17]));
		state[1] = circularLeft(tmp, p0) + tA[(pp8k[isp + 7]) ^ 1];
		state[25] = state[17];
		state[17] = state[9];
		state[9] = tA[1];
		tmp = state[26] + (w[58])
			+ ((state[2] & state[10])
			| ((state[2] | state[10]) & state[18]));
		state[2] = circularLeft(tmp, p0) + tA[(pp8k[isp + 7]) ^ 2];
		state[26] = state[18];
		state[18] = state[10];
		state[10] = tA[2];
		tmp = state[27] + (w[59])
			+ ((state[3] & state[11])
			| ((state[3] | state[11]) & state[19]));
		state[3] = circularLeft(tmp, p0) + tA[(pp8k[isp + 7]) ^ 3];
		state[27] = state[19];
		state[19] = state[11];
		state[11] = tA[3];
		tmp = state[28] + (w[60])
			+ ((state[4] & state[12])
			| ((state[4] | state[12]) & state[20]));
		state[4] = circularLeft(tmp, p0) + tA[(pp8k[isp + 7]) ^ 4];
		state[28] = state[20];
		state[20] = state[12];
		state[12] = tA[4];
		tmp = state[29] + (w[61])
			+ ((state[5] & state[13])
			| ((state[5] | state[13]) & state[21]));
		state[5] = circularLeft(tmp, p0) + tA[(pp8k[isp + 7]) ^ 5];
		state[29] = state[21];
		state[21] = state[13];
		state[13] = tA[5];
		tmp = state[30] + (w[62])
			+ ((state[6] & state[14])
			| ((state[6] | state[14]) & state[22]));
		state[6] = circularLeft(tmp, p0) + tA[(pp8k[isp + 7]) ^ 6];
		state[30] = state[22];
		state[22] = state[14];
		state[14] = tA[6];
		tmp = state[31] + (w[63])
			+ ((state[7] & state[15])
			| ((state[7] | state[15]) & state[23]));
		state[7] = circularLeft(tmp, p0) + tA[(pp8k[isp + 7]) ^ 7];
		state[31] = state[23];
		state[23] = state[15];
		state[15] = tA[7];
	}

	private final void compress(byte[] x, boolean last)
	{
		int tmp;
		fft64(x, 0 + (1 * 0), 1 << 2, 0 + 0);
		fft64(x, 0 + (1 * 2), 1 << 2, 0 + 64);
		int m = q[0];
		int n = q[0 + 64];
		q[0] = m + n;
		q[0 + 64] = m - n;
		for (int u = 0, v = 0; u < 64; u += 4, v += 4 * 2) {
			int t;
			if (u != 0) {
				m = q[0 + u + 0];
				n = q[0 + u + 0 + 64];
				t = ((n * alphaTab[v + 0 * 2]) & 0xFFFF)
					+ ((n * alphaTab[v + 0 * 2]) >> 16);
				q[0 + u + 0] = m + t;
				q[0 + u + 0 + 64] = m - t;
			}
			m = q[0 + u + 1];
			n = q[0 + u + 1 + 64];
			t = ((n * alphaTab[v + 1 * 2]) & 0xFFFF)
				+ ((n * alphaTab[v + 1 * 2]) >> 16);
			q[0 + u + 1] = m + t;
			q[0 + u + 1 + 64] = m - t;
			m = q[0 + u + 2];
			n = q[0 + u + 2 + 64];
			t = ((n * alphaTab[v + 2 * 2]) & 0xFFFF)
				+ ((n * alphaTab[v + 2 * 2]) >> 16);
			q[0 + u + 2] = m + t;
			q[0 + u + 2 + 64] = m - t;
			m = q[0 + u + 3];
			n = q[0 + u + 3 + 64];
			t = ((n * alphaTab[v + 3 * 2]) & 0xFFFF)
				+ ((n * alphaTab[v + 3 * 2]) >> 16);
			q[0 + u + 3] = m + t;
			q[0 + u + 3 + 64] = m - t;
		}
		fft64(x, 0 + (1 * 1), 1 << 2, 0 + 128);
		fft64(x, 0 + (1 * 3), 1 << 2, 0 + 192);
		m = q[0 + 128];
		n = q[0 + 128 + 64];
		q[0 + 128] = m + n;
		q[0 + 128 + 64] = m - n;
		for (int u = 0, v = 0; u < 64; u += 4, v += 4 * 2) {
			int t;
			if (u != 0) {
				m = q[(0 + 128) + u + 0];
				n = q[(0 + 128) + u + 0 + 64];
				t = ((n * alphaTab[v + 0 * 2]) & 0xFFFF)
					+ ((n * alphaTab[v + 0 * 2]) >> 16);
				q[(0 + 128) + u + 0] = m + t;
				q[(0 + 128) + u + 0 + 64] = m - t;
			}
			m = q[(0 + 128) + u + 1];
			n = q[(0 + 128) + u + 1 + 64];
			t = ((n * alphaTab[v + 1 * 2]) & 0xFFFF)
				+ ((n * alphaTab[v + 1 * 2]) >> 16);
			q[(0 + 128) + u + 1] = m + t;
			q[(0 + 128) + u + 1 + 64] = m - t;
			m = q[(0 + 128) + u + 2];
			n = q[(0 + 128) + u + 2 + 64];
			t = ((n * alphaTab[v + 2 * 2]) & 0xFFFF)
				+ ((n * alphaTab[v + 2 * 2]) >> 16);
			q[(0 + 128) + u + 2] = m + t;
			q[(0 + 128) + u + 2 + 64] = m - t;
			m = q[(0 + 128) + u + 3];
			n = q[(0 + 128) + u + 3 + 64];
			t = ((n * alphaTab[v + 3 * 2]) & 0xFFFF)
				+ ((n * alphaTab[v + 3 * 2]) >> 16);
			q[(0 + 128) + u + 3] = m + t;
			q[(0 + 128) + u + 3 + 64] = m - t;
		}
		m = q[0];
		n = q[0 + 128];
		q[0] = m + n;
		q[0 + 128] = m - n;
		for (int u = 0, v = 0; u < 128; u += 4, v += 4 * 1) {
			int t;
			if (u != 0) {
				m = q[0 + u + 0];
				n = q[0 + u + 0 + 128];
				t = ((n * alphaTab[v + 0 * 1]) & 0xFFFF)
					+ ((n * alphaTab[v + 0 * 1]) >> 16);
				q[0 + u + 0] = m + t;
				q[0 + u + 0 + 128] = m - t;
			}
			m = q[0 + u + 1];
			n = q[0 + u + 1 + 128];
			t = ((n * alphaTab[v + 1 * 1]) & 0xFFFF)
				+ ((n * alphaTab[v + 1 * 1]) >> 16);
			q[0 + u + 1] = m + t;
			q[0 + u + 1 + 128] = m - t;
			m = q[0 + u + 2];
			n = q[0 + u + 2 + 128];
			t = ((n * alphaTab[v + 2 * 1]) & 0xFFFF)
				+ ((n * alphaTab[v + 2 * 1]) >> 16);
			q[0 + u + 2] = m + t;
			q[0 + u + 2 + 128] = m - t;
			m = q[0 + u + 3];
			n = q[0 + u + 3 + 128];
			t = ((n * alphaTab[v + 3 * 1]) & 0xFFFF)
				+ ((n * alphaTab[v + 3 * 1]) >> 16);
			q[0 + u + 3] = m + t;
			q[0 + u + 3 + 128] = m - t;
		}
		if (last) {
			for (int i = 0; i < 256; i++) {
				int tq = q[i] + yoffF[i];
				tq = ((tq & 0xFFFF) + (tq >> 16));
				tq = ((tq & 0xFF) - (tq >> 8));
				tq = ((tq & 0xFF) - (tq >> 8));
				q[i] = (tq <= 128 ? tq : tq - 257);
			}
		} else {
			for (int i = 0; i < 256; i++) {
				int tq = q[i] + yoffN[i];
				tq = ((tq & 0xFFFF) + (tq >> 16));
				tq = ((tq & 0xFF) - (tq >> 8));
				tq = ((tq & 0xFF) - (tq >> 8));
				q[i] = (tq <= 128 ? tq : tq - 257);
			}
		}

		System.arraycopy(state, 0, tmpState, 0, 32);

		for (int i = 0; i < 32; i += 8) {
			state[i + 0] ^= decodeLEInt(x, 4 * (i + 0));
			state[i + 1] ^= decodeLEInt(x, 4 * (i + 1));
			state[i + 2] ^= decodeLEInt(x, 4 * (i + 2));
			state[i + 3] ^= decodeLEInt(x, 4 * (i + 3));
			state[i + 4] ^= decodeLEInt(x, 4 * (i + 4));
			state[i + 5] ^= decodeLEInt(x, 4 * (i + 5));
			state[i + 6] ^= decodeLEInt(x, 4 * (i + 6));
			state[i + 7] ^= decodeLEInt(x, 4 * (i + 7));
		}
		for (int u = 0; u < 64; u += 8) {
			int v = wbp[(u >> 3) + 0];
			w[u + 0] = (((q[v + 2 * 0 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 0 + 1]) * 185) << 16);
			w[u + 1] = (((q[v + 2 * 1 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 1 + 1]) * 185) << 16);
			w[u + 2] = (((q[v + 2 * 2 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 2 + 1]) * 185) << 16);
			w[u + 3] = (((q[v + 2 * 3 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 3 + 1]) * 185) << 16);
			w[u + 4] = (((q[v + 2 * 4 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 4 + 1]) * 185) << 16);
			w[u + 5] = (((q[v + 2 * 5 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 5 + 1]) * 185) << 16);
			w[u + 6] = (((q[v + 2 * 6 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 6 + 1]) * 185) << 16);
			w[u + 7] = (((q[v + 2 * 7 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 7 + 1]) * 185) << 16);
		}
		oneRound(0, 3, 23, 17, 27);
		for (int u = 0; u < 64; u += 8) {
			int v = wbp[(u >> 3) + 8];
			w[u + 0] = (((q[v + 2 * 0 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 0 + 1]) * 185) << 16);
			w[u + 1] = (((q[v + 2 * 1 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 1 + 1]) * 185) << 16);
			w[u + 2] = (((q[v + 2 * 2 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 2 + 1]) * 185) << 16);
			w[u + 3] = (((q[v + 2 * 3 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 3 + 1]) * 185) << 16);
			w[u + 4] = (((q[v + 2 * 4 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 4 + 1]) * 185) << 16);
			w[u + 5] = (((q[v + 2 * 5 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 5 + 1]) * 185) << 16);
			w[u + 6] = (((q[v + 2 * 6 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 6 + 1]) * 185) << 16);
			w[u + 7] = (((q[v + 2 * 7 + 0]) * 185) & 0xFFFF)
				+ (((q[v + 2 * 7 + 1]) * 185) << 16);
		}
		oneRound(1, 28, 19, 22, 7);
		for (int u = 0; u < 64; u += 8) {
			int v = wbp[(u >> 3) + 16];
			w[u + 0] = (((q[v + 2 * 0 + (-256)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 0 + (-128)]) * 233) << 16);
			w[u + 1] = (((q[v + 2 * 1 + (-256)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 1 + (-128)]) * 233) << 16);
			w[u + 2] = (((q[v + 2 * 2 + (-256)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 2 + (-128)]) * 233) << 16);
			w[u + 3] = (((q[v + 2 * 3 + (-256)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 3 + (-128)]) * 233) << 16);
			w[u + 4] = (((q[v + 2 * 4 + (-256)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 4 + (-128)]) * 233) << 16);
			w[u + 5] = (((q[v + 2 * 5 + (-256)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 5 + (-128)]) * 233) << 16);
			w[u + 6] = (((q[v + 2 * 6 + (-256)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 6 + (-128)]) * 233) << 16);
			w[u + 7] = (((q[v + 2 * 7 + (-256)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 7 + (-128)]) * 233) << 16);
		}
		oneRound(2, 29, 9, 15, 5);
		for (int u = 0; u < 64; u += 8) {
			int v = wbp[(u >> 3) + 24];
			w[u + 0] = (((q[v + 2 * 0 + (-383)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 0 + (-255)]) * 233) << 16);
			w[u + 1] = (((q[v + 2 * 1 + (-383)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 1 + (-255)]) * 233) << 16);
			w[u + 2] = (((q[v + 2 * 2 + (-383)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 2 + (-255)]) * 233) << 16);
			w[u + 3] = (((q[v + 2 * 3 + (-383)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 3 + (-255)]) * 233) << 16);
			w[u + 4] = (((q[v + 2 * 4 + (-383)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 4 + (-255)]) * 233) << 16);
			w[u + 5] = (((q[v + 2 * 5 + (-383)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 5 + (-255)]) * 233) << 16);
			w[u + 6] = (((q[v + 2 * 6 + (-383)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 6 + (-255)]) * 233) << 16);
			w[u + 7] = (((q[v + 2 * 7 + (-383)]) * 233) & 0xFFFF)
				+ (((q[v + 2 * 7 + (-255)]) * 233) << 16);
		}
		oneRound(3, 4, 13, 10, 25);

		{
			int tA0 = circularLeft(state[0], 4);
			int tA1 = circularLeft(state[1], 4);
			int tA2 = circularLeft(state[2], 4);
			int tA3 = circularLeft(state[3], 4);
			int tA4 = circularLeft(state[4], 4);
			int tA5 = circularLeft(state[5], 4);
			int tA6 = circularLeft(state[6], 4);
			int tA7 = circularLeft(state[7], 4);
			tmp = state[24] + (tmpState[0]) + (((state[8]
				^ state[16]) & state[0]) ^ state[16]);
			state[0] = circularLeft(tmp, 13) + tA5;
			state[24] = state[16];
			state[16] = state[8];
			state[8] = tA0;
			tmp = state[25] + (tmpState[1]) + (((state[9]
				^ state[17]) & state[1]) ^ state[17]);
			state[1] = circularLeft(tmp, 13) + tA4;
			state[25] = state[17];
			state[17] = state[9];
			state[9] = tA1;
			tmp = state[26] + (tmpState[2]) + (((state[10]
				^ state[18]) & state[2]) ^ state[18]);
			state[2] = circularLeft(tmp, 13) + tA7;
			state[26] = state[18];
			state[18] = state[10];
			state[10] = tA2;
			tmp = state[27] + (tmpState[3]) + (((state[11]
				^ state[19]) & state[3]) ^ state[19]);
			state[3] = circularLeft(tmp, 13) + tA6;
			state[27] = state[19];
			state[19] = state[11];
			state[11] = tA3;
			tmp = state[28] + (tmpState[4]) + (((state[12]
				^ state[20]) & state[4]) ^ state[20]);
			state[4] = circularLeft(tmp, 13) + tA1;
			state[28] = state[20];
			state[20] = state[12];
			state[12] = tA4;
			tmp = state[29] + (tmpState[5]) + (((state[13]
				^ state[21]) & state[5]) ^ state[21]);
			state[5] = circularLeft(tmp, 13) + tA0;
			state[29] = state[21];
			state[21] = state[13];
			state[13] = tA5;
			tmp = state[30] + (tmpState[6]) + (((state[14]
				^ state[22]) & state[6]) ^ state[22]);
			state[6] = circularLeft(tmp, 13) + tA3;
			state[30] = state[22];
			state[22] = state[14];
			state[14] = tA6;
			tmp = state[31] + (tmpState[7]) + (((state[15]
				^ state[23]) & state[7]) ^ state[23]);
			state[7] = circularLeft(tmp, 13) + tA2;
			state[31] = state[23];
			state[23] = state[15];
			state[15] = tA7;
		}
		{
			int tA0 = circularLeft(state[0], 13);
			int tA1 = circularLeft(state[1], 13);
			int tA2 = circularLeft(state[2], 13);
			int tA3 = circularLeft(state[3], 13);
			int tA4 = circularLeft(state[4], 13);
			int tA5 = circularLeft(state[5], 13);
			int tA6 = circularLeft(state[6], 13);
			int tA7 = circularLeft(state[7], 13);
			tmp = state[24] + (tmpState[8]) + (((state[8]
				^ state[16]) & state[0]) ^ state[16]);
			state[0] = circularLeft(tmp, 10) + tA7;
			state[24] = state[16];
			state[16] = state[8];
			state[8] = tA0;
			tmp = state[25] + (tmpState[9]) + (((state[9]
				^ state[17]) & state[1]) ^ state[17]);
			state[1] = circularLeft(tmp, 10) + tA6;
			state[25] = state[17];
			state[17] = state[9];
			state[9] = tA1;
			tmp = state[26] + (tmpState[10]) + (((state[10]
				^ state[18]) & state[2]) ^ state[18]);
			state[2] = circularLeft(tmp, 10) + tA5;
			state[26] = state[18];
			state[18] = state[10];
			state[10] = tA2;
			tmp = state[27] + (tmpState[11]) + (((state[11]
				^ state[19]) & state[3]) ^ state[19]);
			state[3] = circularLeft(tmp, 10) + tA4;
			state[27] = state[19];
			state[19] = state[11];
			state[11] = tA3;
			tmp = state[28] + (tmpState[12]) + (((state[12]
				^ state[20]) & state[4]) ^ state[20]);
			state[4] = circularLeft(tmp, 10) + tA3;
			state[28] = state[20];
			state[20] = state[12];
			state[12] = tA4;
			tmp = state[29] + (tmpState[13]) + (((state[13]
				^ state[21]) & state[5]) ^ state[21]);
			state[5] = circularLeft(tmp, 10) + tA2;
			state[29] = state[21];
			state[21] = state[13];
			state[13] = tA5;
			tmp = state[30] + (tmpState[14]) + (((state[14]
				^ state[22]) & state[6]) ^ state[22]);
			state[6] = circularLeft(tmp, 10) + tA1;
			state[30] = state[22];
			state[22] = state[14];
			state[14] = tA6;
			tmp = state[31] + (tmpState[15]) + (((state[15]
				^ state[23]) & state[7]) ^ state[23]);
			state[7] = circularLeft(tmp, 10) + tA0;
			state[31] = state[23];
			state[23] = state[15];
			state[15] = tA7;
		}
		{
			int tA0 = circularLeft(state[0], 10);
			int tA1 = circularLeft(state[1], 10);
			int tA2 = circularLeft(state[2], 10);
			int tA3 = circularLeft(state[3], 10);
			int tA4 = circularLeft(state[4], 10);
			int tA5 = circularLeft(state[5], 10);
			int tA6 = circularLeft(state[6], 10);
			int tA7 = circularLeft(state[7], 10);
			tmp = state[24] + (tmpState[16]) + (((state[8]
				^ state[16]) & state[0]) ^ state[16]);
			state[0] = circularLeft(tmp, 25) + tA4;
			state[24] = state[16];
			state[16] = state[8];
			state[8] = tA0;
			tmp = state[25] + (tmpState[17]) + (((state[9]
				^ state[17]) & state[1]) ^ state[17]);
			state[1] = circularLeft(tmp, 25) + tA5;
			state[25] = state[17];
			state[17] = state[9];
			state[9] = tA1;
			tmp = state[26] + (tmpState[18]) + (((state[10]
				^ state[18]) & state[2]) ^ state[18]);
			state[2] = circularLeft(tmp, 25) + tA6;
			state[26] = state[18];
			state[18] = state[10];
			state[10] = tA2;
			tmp = state[27] + (tmpState[19]) + (((state[11]
				^ state[19]) & state[3]) ^ state[19]);
			state[3] = circularLeft(tmp, 25) + tA7;
			state[27] = state[19];
			state[19] = state[11];
			state[11] = tA3;
			tmp = state[28] + (tmpState[20]) + (((state[12]
				^ state[20]) & state[4]) ^ state[20]);
			state[4] = circularLeft(tmp, 25) + tA0;
			state[28] = state[20];
			state[20] = state[12];
			state[12] = tA4;
			tmp = state[29] + (tmpState[21]) + (((state[13]
				^ state[21]) & state[5]) ^ state[21]);
			state[5] = circularLeft(tmp, 25) + tA1;
			state[29] = state[21];
			state[21] = state[13];
			state[13] = tA5;
			tmp = state[30] + (tmpState[22]) + (((state[14]
				^ state[22]) & state[6]) ^ state[22]);
			state[6] = circularLeft(tmp, 25) + tA2;
			state[30] = state[22];
			state[22] = state[14];
			state[14] = tA6;
			tmp = state[31] + (tmpState[23]) + (((state[15]
				^ state[23]) & state[7]) ^ state[23]);
			state[7] = circularLeft(tmp, 25) + tA3;
			state[31] = state[23];
			state[23] = state[15];
			state[15] = tA7;
		}
		{
			int tA0 = circularLeft(state[0], 25);
			int tA1 = circularLeft(state[1], 25);
			int tA2 = circularLeft(state[2], 25);
			int tA3 = circularLeft(state[3], 25);
			int tA4 = circularLeft(state[4], 25);
			int tA5 = circularLeft(state[5], 25);
			int tA6 = circularLeft(state[6], 25);
			int tA7 = circularLeft(state[7], 25);
			tmp = state[24] + (tmpState[24]) + (((state[8]
				^ state[16]) & state[0]) ^ state[16]);
			state[0] = circularLeft(tmp, 4) + tA1;
			state[24] = state[16];
			state[16] = state[8];
			state[8] = tA0;
			tmp = state[25] + (tmpState[25]) + (((state[9]
				^ state[17]) & state[1]) ^ state[17]);
			state[1] = circularLeft(tmp, 4) + tA0;
			state[25] = state[17];
			state[17] = state[9];
			state[9] = tA1;
			tmp = state[26] + (tmpState[26]) + (((state[10]
				^ state[18]) & state[2]) ^ state[18]);
			state[2] = circularLeft(tmp, 4) + tA3;
			state[26] = state[18];
			state[18] = state[10];
			state[10] = tA2;
			tmp = state[27] + (tmpState[27]) + (((state[11]
				^ state[19]) & state[3]) ^ state[19]);
			state[3] = circularLeft(tmp, 4) + tA2;
			state[27] = state[19];
			state[19] = state[11];
			state[11] = tA3;
			tmp = state[28] + (tmpState[28]) + (((state[12]
				^ state[20]) & state[4]) ^ state[20]);
			state[4] = circularLeft(tmp, 4) + tA5;
			state[28] = state[20];
			state[20] = state[12];
			state[12] = tA4;
			tmp = state[29] + (tmpState[29]) + (((state[13]
				^ state[21]) & state[5]) ^ state[21]);
			state[5] = circularLeft(tmp, 4) + tA4;
			state[29] = state[21];
			state[21] = state[13];
			state[13] = tA5;
			tmp = state[30] + (tmpState[30]) + (((state[14]
				^ state[22]) & state[6]) ^ state[22]);
			state[6] = circularLeft(tmp, 4) + tA7;
			state[30] = state[22];
			state[22] = state[14];
			state[14] = tA6;
			tmp = state[31] + (tmpState[31]) + (((state[15]
				^ state[23]) & state[7]) ^ state[23]);
			state[7] = circularLeft(tmp, 4) + tA6;
			state[31] = state[23];
			state[23] = state[15];
			state[15] = tA7;
		}
	}

	/** @see Digest */
	public String toString()
	{
		return "SIMD-" + (getDigestLength() << 3);
	}
}
