// $Id: RIPEMD160.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the RIPEMD-160 digest algorithm under the
 * {@link Digest} API.</p>
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

public class RIPEMD160 extends MDHelper {

	/**
	 * Build the object.
	 */
	public RIPEMD160()
	{
		super(true, 8);
	}

	private int[] currentVal, X;

	/** @see Digest */
	public Digest copy()
	{
		RIPEMD160 d = new RIPEMD160();
		System.arraycopy(currentVal, 0, d.currentVal, 0,
			currentVal.length);
		return copyState(d);
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 20;
	}

	/** @see Digest */
	public int getBlockLength()
	{
		return 64;
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		currentVal[0] = (int)0x67452301;
		currentVal[1] = (int)0xEFCDAB89;
		currentVal[2] = (int)0x98BADCFE;
		currentVal[3] = (int)0x10325476;
		currentVal[4] = (int)0xC3D2E1F0;
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		makeMDPadding();
		for (int i = 0; i < 5; i ++)
			encodeLEInt(currentVal[i],
				output, outputOffset + 4 * i);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		currentVal = new int[5];
		X = new int[16];
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
		return (buf[off + 0] & 0xFF)
			| ((buf[off + 1] & 0xFF) << 8)
			| ((buf[off + 2] & 0xFF) << 16)
			| ((buf[off + 3] & 0xFF) << 24);
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
	static private final int circularLeft(int x, int n)
	{
		return (x << n) | (x >>> (32 - n));
	}

	private static final int[] r1 = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
		3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
		4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
	};

	private static final int[] r2 = {
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
		12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
	};

	private static final int[] s1 = {
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
		9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
	};

	private static final int[] s2 = {
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
		8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
	};

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		int H0, H1, H2, H3, H4;
		int A1, B1, C1, D1, E1;
		int A2, B2, C2, D2, E2;

		H0 = A1 = A2 = currentVal[0];
		H1 = B1 = B2 = currentVal[1];
		H2 = C1 = C2 = currentVal[2];
		H3 = D1 = D2 = currentVal[3];
		H4 = E1 = E2 = currentVal[4];

		for (int i = 0, j = 0; i < 16; i ++, j += 4)
			X[i] = decodeLEInt(data, j);

		for (int i = 0; i < 16; i ++) {
			int T1 = A1 + (B1 ^ C1 ^ D1)
				+ X[i];
			T1 = ((T1 << s1[i]) | (T1 >>> (32 - s1[i]))) + E1;
			A1 = E1; E1 = D1; D1 = (C1 << 10) | (C1 >>> 22);
			C1 = B1; B1 = T1;
		}
		for (int i = 16; i < 32; i ++) {
			int T1 = A1 + (((C1 ^ D1) & B1) ^ D1)
				+ X[r1[i]] + (int)0x5A827999;
			T1 = ((T1 << s1[i]) | (T1 >>> (32 - s1[i]))) + E1;
			A1 = E1; E1 = D1; D1 = (C1 << 10) | (C1 >>> 22);
			C1 = B1; B1 = T1;
		}
		for (int i = 32; i < 48; i ++) {
			int T1 = A1 + ((B1 | ~C1) ^ D1)
				+ X[r1[i]] + (int)0x6ED9EBA1;
			T1 = ((T1 << s1[i]) | (T1 >>> (32 - s1[i]))) + E1;
			A1 = E1; E1 = D1; D1 = (C1 << 10) | (C1 >>> 22);
			C1 = B1; B1 = T1;
		}
		for (int i = 48; i < 64; i ++) {
			int T1 = A1 + (((B1 ^ C1) & D1) ^ C1)
				+ X[r1[i]] + (int)0x8F1BBCDC;
			T1 = ((T1 << s1[i]) | (T1 >>> (32 - s1[i]))) + E1;
			A1 = E1; E1 = D1; D1 = (C1 << 10) | (C1 >>> 22);
			C1 = B1; B1 = T1;
		}
		for (int i = 64; i < 80; i ++) {
			int T1 = A1 + (B1 ^ (C1 | ~D1))
				+ X[r1[i]] + (int)0xA953FD4E;
			T1 = ((T1 << s1[i]) | (T1 >>> (32 - s1[i]))) + E1;
			A1 = E1; E1 = D1; D1 = (C1 << 10) | (C1 >>> 22);
			C1 = B1; B1 = T1;
		}

		for (int i = 0; i < 16; i ++) {
			int T2 = A2 + (B2 ^ (C2 | ~D2))
				+ X[r2[i]] + (int)0x50A28BE6;
			T2 = ((T2 << s2[i]) | (T2 >>> (32 - s2[i]))) + E2;
			A2 = E2; E2 = D2; D2 = (C2 << 10) | (C2 >>> 22);
			C2 = B2; B2 = T2;
		}
		for (int i = 16; i < 32; i ++) {
			int T2 = A2 + (((B2 ^ C2) & D2) ^ C2)
				+ X[r2[i]] + (int)0x5C4DD124;
			T2 = ((T2 << s2[i]) | (T2 >>> (32 - s2[i]))) + E2;
			A2 = E2; E2 = D2; D2 = (C2 << 10) | (C2 >>> 22);
			C2 = B2; B2 = T2;
		}
		for (int i = 32; i < 48; i ++) {
			int T2 = A2 + ((B2 | ~C2) ^ D2)
				+ X[r2[i]] + (int)0x6D703EF3;
			T2 = ((T2 << s2[i]) | (T2 >>> (32 - s2[i]))) + E2;
			A2 = E2; E2 = D2; D2 = (C2 << 10) | (C2 >>> 22);
			C2 = B2; B2 = T2;
		}
		for (int i = 48; i < 64; i ++) {
			int T2 = A2 + (((C2 ^ D2) & B2) ^ D2)
				+ X[r2[i]] + (int)0x7A6D76E9;
			T2 = ((T2 << s2[i]) | (T2 >>> (32 - s2[i]))) + E2;
			A2 = E2; E2 = D2; D2 = (C2 << 10) | (C2 >>> 22);
			C2 = B2; B2 = T2;
		}
		for (int i = 64; i < 80; i ++) {
			int T2 = A2 + (B2 ^ C2 ^ D2)
				+ X[r2[i]];
			T2 = ((T2 << s2[i]) | (T2 >>> (32 - s2[i]))) + E2;
			A2 = E2; E2 = D2; D2 = (C2 << 10) | (C2 >>> 22);
			C2 = B2; B2 = T2;
		}

		int T = H1 + C1 + D2;
		currentVal[1] = H2 + D1 + E2;
		currentVal[2] = H3 + E1 + A2;
		currentVal[3] = H4 + A1 + B2;
		currentVal[4] = H0 + B1 + C2;
		currentVal[0] = T;
	}

	/** @see Digest */
	public String toString()
	{
		return "RIPEMD-160";
	}
}
