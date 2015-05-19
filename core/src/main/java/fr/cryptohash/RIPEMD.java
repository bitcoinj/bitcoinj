// $Id: RIPEMD.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the RIPEMD digest algorithm under the {@link
 * Digest} API. This is the original RIPEMD, <strong>not</strong> the
 * strengthened variants RIPEMD-128 or RIPEMD-160. A collision for this
 * RIPEMD has been published in 2004.</p>
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

public class RIPEMD extends MDHelper {

	/*
	 * TODO: merge some of this code with that of RIPEMD128.
	 */

	/**
	 * Build the object.
	 */
	public RIPEMD()
	{
		super(true, 8);
	}

	private int[] currentVal, X;

	/** @see Digest */
	public Digest copy()
	{
		RIPEMD d = new RIPEMD();
		System.arraycopy(currentVal, 0, d.currentVal, 0,
			currentVal.length);
		return copyState(d);
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 16;
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
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		makeMDPadding();
		for (int i = 0; i < 4; i ++)
			encodeLEInt(currentVal[i],
				output, outputOffset + 4 * i);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		currentVal = new int[4];
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
		1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2
	};

	private static final int[] r2 = {
		5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
		6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
		15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
		8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14
	};

	private static final int[] s1 = {
		11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
		7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
		11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
		11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12
	};

	private static final int[] s2 = {
		8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
		9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
		9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
		15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8
	};

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		int H0, H1, H2, H3;
		int A1, B1, C1, D1;
		int A2, B2, C2, D2;
		int tmp;

		H0 = A1 = A2 = currentVal[0];
		H1 = B1 = B2 = currentVal[1];
		H2 = C1 = C2 = currentVal[2];
		H3 = D1 = D2 = currentVal[3];

		for (int i = 0, j = 0; i < 16; i ++, j += 4)
			X[i] = decodeLEInt(data, j);

		tmp = A1 + (((C1 ^ D1) & B1) ^ D1) + X[0];
		A1 = (tmp << 11) | (tmp >>> (32 - 11));
		tmp = D1 + (((B1 ^ C1) & A1) ^ C1) + X[1];
		D1 = (tmp << 14) | (tmp >>> (32 - 14));
		tmp = C1 + (((A1 ^ B1) & D1) ^ B1) + X[2];
		C1 = (tmp << 15) | (tmp >>> (32 - 15));
		tmp = B1 + (((D1 ^ A1) & C1) ^ A1) + X[3];
		B1 = (tmp << 12) | (tmp >>> (32 - 12));
		tmp = A1 + (((C1 ^ D1) & B1) ^ D1) + X[4];
		A1 = (tmp << 5) | (tmp >>> (32 - 5));
		tmp = D1 + (((B1 ^ C1) & A1) ^ C1) + X[5];
		D1 = (tmp << 8) | (tmp >>> (32 - 8));
		tmp = C1 + (((A1 ^ B1) & D1) ^ B1) + X[6];
		C1 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = B1 + (((D1 ^ A1) & C1) ^ A1) + X[7];
		B1 = (tmp << 9) | (tmp >>> (32 - 9));
		tmp = A1 + (((C1 ^ D1) & B1) ^ D1) + X[8];
		A1 = (tmp << 11) | (tmp >>> (32 - 11));
		tmp = D1 + (((B1 ^ C1) & A1) ^ C1) + X[9];
		D1 = (tmp << 13) | (tmp >>> (32 - 13));
		tmp = C1 + (((A1 ^ B1) & D1) ^ B1) + X[10];
		C1 = (tmp << 14) | (tmp >>> (32 - 14));
		tmp = B1 + (((D1 ^ A1) & C1) ^ A1) + X[11];
		B1 = (tmp << 15) | (tmp >>> (32 - 15));
		tmp = A1 + (((C1 ^ D1) & B1) ^ D1) + X[12];
		A1 = (tmp << 6) | (tmp >>> (32 - 6));
		tmp = D1 + (((B1 ^ C1) & A1) ^ C1) + X[13];
		D1 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = C1 + (((A1 ^ B1) & D1) ^ B1) + X[14];
		C1 = (tmp << 9) | (tmp >>> (32 - 9));
		tmp = B1 + (((D1 ^ A1) & C1) ^ A1) + X[15];
		B1 = (tmp << 8) | (tmp >>> (32 - 8));

		tmp = A1 + ((B1 & C1) | ((B1 | C1) & D1)) + X[7] + 0x5A827999;
		A1 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = D1 + ((A1 & B1) | ((A1 | B1) & C1)) + X[4] + 0x5A827999;
		D1 = (tmp << 6) | (tmp >>> (32 - 6));
		tmp = C1 + ((D1 & A1) | ((D1 | A1) & B1)) + X[13] + 0x5A827999;
		C1 = (tmp << 8) | (tmp >>> (32 - 8));
		tmp = B1 + ((C1 & D1) | ((C1 | D1) & A1)) + X[1] + 0x5A827999;
		B1 = (tmp << 13) | (tmp >>> (32 - 13));
		tmp = A1 + ((B1 & C1) | ((B1 | C1) & D1)) + X[10] + 0x5A827999;
		A1 = (tmp << 11) | (tmp >>> (32 - 11));
		tmp = D1 + ((A1 & B1) | ((A1 | B1) & C1)) + X[6] + 0x5A827999;
		D1 = (tmp << 9) | (tmp >>> (32 - 9));
		tmp = C1 + ((D1 & A1) | ((D1 | A1) & B1)) + X[15] + 0x5A827999;
		C1 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = B1 + ((C1 & D1) | ((C1 | D1) & A1)) + X[3] + 0x5A827999;
		B1 = (tmp << 15) | (tmp >>> (32 - 15));
		tmp = A1 + ((B1 & C1) | ((B1 | C1) & D1)) + X[12] + 0x5A827999;
		A1 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = D1 + ((A1 & B1) | ((A1 | B1) & C1)) + X[0] + 0x5A827999;
		D1 = (tmp << 12) | (tmp >>> (32 - 12));
		tmp = C1 + ((D1 & A1) | ((D1 | A1) & B1)) + X[9] + 0x5A827999;
		C1 = (tmp << 15) | (tmp >>> (32 - 15));
		tmp = B1 + ((C1 & D1) | ((C1 | D1) & A1)) + X[5] + 0x5A827999;
		B1 = (tmp << 9) | (tmp >>> (32 - 9));
		tmp = A1 + ((B1 & C1) | ((B1 | C1) & D1)) + X[14] + 0x5A827999;
		A1 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = D1 + ((A1 & B1) | ((A1 | B1) & C1)) + X[2] + 0x5A827999;
		D1 = (tmp << 11) | (tmp >>> (32 - 11));
		tmp = C1 + ((D1 & A1) | ((D1 | A1) & B1)) + X[11] + 0x5A827999;
		C1 = (tmp << 13) | (tmp >>> (32 - 13));
		tmp = B1 + ((C1 & D1) | ((C1 | D1) & A1)) + X[8] + 0x5A827999;
		B1 = (tmp << 12) | (tmp >>> (32 - 12));

		tmp = A1 + (B1 ^ C1 ^ D1) + X[3] + 0x6ED9EBA1;
		A1 = (tmp << 11) | (tmp >>> (32 - 11));
		tmp = D1 + (A1 ^ B1 ^ C1) + X[10] + 0x6ED9EBA1;
		D1 = (tmp << 13) | (tmp >>> (32 - 13));
		tmp = C1 + (D1 ^ A1 ^ B1) + X[2] + 0x6ED9EBA1;
		C1 = (tmp << 14) | (tmp >>> (32 - 14));
		tmp = B1 + (C1 ^ D1 ^ A1) + X[4] + 0x6ED9EBA1;
		B1 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = A1 + (B1 ^ C1 ^ D1) + X[9] + 0x6ED9EBA1;
		A1 = (tmp << 14) | (tmp >>> (32 - 14));
		tmp = D1 + (A1 ^ B1 ^ C1) + X[15] + 0x6ED9EBA1;
		D1 = (tmp << 9) | (tmp >>> (32 - 9));
		tmp = C1 + (D1 ^ A1 ^ B1) + X[8] + 0x6ED9EBA1;
		C1 = (tmp << 13) | (tmp >>> (32 - 13));
		tmp = B1 + (C1 ^ D1 ^ A1) + X[1] + 0x6ED9EBA1;
		B1 = (tmp << 15) | (tmp >>> (32 - 15));
		tmp = A1 + (B1 ^ C1 ^ D1) + X[14] + 0x6ED9EBA1;
		A1 = (tmp << 6) | (tmp >>> (32 - 6));
		tmp = D1 + (A1 ^ B1 ^ C1) + X[7] + 0x6ED9EBA1;
		D1 = (tmp << 8) | (tmp >>> (32 - 8));
		tmp = C1 + (D1 ^ A1 ^ B1) + X[0] + 0x6ED9EBA1;
		C1 = (tmp << 13) | (tmp >>> (32 - 13));
		tmp = B1 + (C1 ^ D1 ^ A1) + X[6] + 0x6ED9EBA1;
		B1 = (tmp << 6) | (tmp >>> (32 - 6));
		tmp = A1 + (B1 ^ C1 ^ D1) + X[11] + 0x6ED9EBA1;
		A1 = (tmp << 12) | (tmp >>> (32 - 12));
		tmp = D1 + (A1 ^ B1 ^ C1) + X[13] + 0x6ED9EBA1;
		D1 = (tmp << 5) | (tmp >>> (32 - 5));
		tmp = C1 + (D1 ^ A1 ^ B1) + X[5] + 0x6ED9EBA1;
		C1 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = B1 + (C1 ^ D1 ^ A1) + X[12] + 0x6ED9EBA1;
		B1 = (tmp << 5) | (tmp >>> (32 - 5));

		tmp = A2 + (((C2 ^ D2) & B2) ^ D2) + X[0] + 0x50A28BE6;
		A2 = (tmp << 11) | (tmp >>> (32 - 11));
		tmp = D2 + (((B2 ^ C2) & A2) ^ C2) + X[1] + 0x50A28BE6;
		D2 = (tmp << 14) | (tmp >>> (32 - 14));
		tmp = C2 + (((A2 ^ B2) & D2) ^ B2) + X[2] + 0x50A28BE6;
		C2 = (tmp << 15) | (tmp >>> (32 - 15));
		tmp = B2 + (((D2 ^ A2) & C2) ^ A2) + X[3] + 0x50A28BE6;
		B2 = (tmp << 12) | (tmp >>> (32 - 12));
		tmp = A2 + (((C2 ^ D2) & B2) ^ D2) + X[4] + 0x50A28BE6;
		A2 = (tmp << 5) | (tmp >>> (32 - 5));
		tmp = D2 + (((B2 ^ C2) & A2) ^ C2) + X[5] + 0x50A28BE6;
		D2 = (tmp << 8) | (tmp >>> (32 - 8));
		tmp = C2 + (((A2 ^ B2) & D2) ^ B2) + X[6] + 0x50A28BE6;
		C2 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = B2 + (((D2 ^ A2) & C2) ^ A2) + X[7] + 0x50A28BE6;
		B2 = (tmp << 9) | (tmp >>> (32 - 9));
		tmp = A2 + (((C2 ^ D2) & B2) ^ D2) + X[8] + 0x50A28BE6;
		A2 = (tmp << 11) | (tmp >>> (32 - 11));
		tmp = D2 + (((B2 ^ C2) & A2) ^ C2) + X[9] + 0x50A28BE6;
		D2 = (tmp << 13) | (tmp >>> (32 - 13));
		tmp = C2 + (((A2 ^ B2) & D2) ^ B2) + X[10] + 0x50A28BE6;
		C2 = (tmp << 14) | (tmp >>> (32 - 14));
		tmp = B2 + (((D2 ^ A2) & C2) ^ A2) + X[11] + 0x50A28BE6;
		B2 = (tmp << 15) | (tmp >>> (32 - 15));
		tmp = A2 + (((C2 ^ D2) & B2) ^ D2) + X[12] + 0x50A28BE6;
		A2 = (tmp << 6) | (tmp >>> (32 - 6));
		tmp = D2 + (((B2 ^ C2) & A2) ^ C2) + X[13] + 0x50A28BE6;
		D2 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = C2 + (((A2 ^ B2) & D2) ^ B2) + X[14] + 0x50A28BE6;
		C2 = (tmp << 9) | (tmp >>> (32 - 9));
		tmp = B2 + (((D2 ^ A2) & C2) ^ A2) + X[15] + 0x50A28BE6;
		B2 = (tmp << 8) | (tmp >>> (32 - 8));

		tmp = A2 + ((B2 & C2) | ((B2 | C2) & D2)) + X[7];
		A2 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = D2 + ((A2 & B2) | ((A2 | B2) & C2)) + X[4];
		D2 = (tmp << 6) | (tmp >>> (32 - 6));
		tmp = C2 + ((D2 & A2) | ((D2 | A2) & B2)) + X[13];
		C2 = (tmp << 8) | (tmp >>> (32 - 8));
		tmp = B2 + ((C2 & D2) | ((C2 | D2) & A2)) + X[1];
		B2 = (tmp << 13) | (tmp >>> (32 - 13));
		tmp = A2 + ((B2 & C2) | ((B2 | C2) & D2)) + X[10];
		A2 = (tmp << 11) | (tmp >>> (32 - 11));
		tmp = D2 + ((A2 & B2) | ((A2 | B2) & C2)) + X[6];
		D2 = (tmp << 9) | (tmp >>> (32 - 9));
		tmp = C2 + ((D2 & A2) | ((D2 | A2) & B2)) + X[15];
		C2 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = B2 + ((C2 & D2) | ((C2 | D2) & A2)) + X[3];
		B2 = (tmp << 15) | (tmp >>> (32 - 15));
		tmp = A2 + ((B2 & C2) | ((B2 | C2) & D2)) + X[12];
		A2 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = D2 + ((A2 & B2) | ((A2 | B2) & C2)) + X[0];
		D2 = (tmp << 12) | (tmp >>> (32 - 12));
		tmp = C2 + ((D2 & A2) | ((D2 | A2) & B2)) + X[9];
		C2 = (tmp << 15) | (tmp >>> (32 - 15));
		tmp = B2 + ((C2 & D2) | ((C2 | D2) & A2)) + X[5];
		B2 = (tmp << 9) | (tmp >>> (32 - 9));
		tmp = A2 + ((B2 & C2) | ((B2 | C2) & D2)) + X[14];
		A2 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = D2 + ((A2 & B2) | ((A2 | B2) & C2)) + X[2];
		D2 = (tmp << 11) | (tmp >>> (32 - 11));
		tmp = C2 + ((D2 & A2) | ((D2 | A2) & B2)) + X[11];
		C2 = (tmp << 13) | (tmp >>> (32 - 13));
		tmp = B2 + ((C2 & D2) | ((C2 | D2) & A2)) + X[8];
		B2 = (tmp << 12) | (tmp >>> (32 - 12));

		tmp = A2 + (B2 ^ C2 ^ D2) + X[3] + 0x5C4DD124;
		A2 = (tmp << 11) | (tmp >>> (32 - 11));
		tmp = D2 + (A2 ^ B2 ^ C2) + X[10] + 0x5C4DD124;
		D2 = (tmp << 13) | (tmp >>> (32 - 13));
		tmp = C2 + (D2 ^ A2 ^ B2) + X[2] + 0x5C4DD124;
		C2 = (tmp << 14) | (tmp >>> (32 - 14));
		tmp = B2 + (C2 ^ D2 ^ A2) + X[4] + 0x5C4DD124;
		B2 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = A2 + (B2 ^ C2 ^ D2) + X[9] + 0x5C4DD124;
		A2 = (tmp << 14) | (tmp >>> (32 - 14));
		tmp = D2 + (A2 ^ B2 ^ C2) + X[15] + 0x5C4DD124;
		D2 = (tmp << 9) | (tmp >>> (32 - 9));
		tmp = C2 + (D2 ^ A2 ^ B2) + X[8] + 0x5C4DD124;
		C2 = (tmp << 13) | (tmp >>> (32 - 13));
		tmp = B2 + (C2 ^ D2 ^ A2) + X[1] + 0x5C4DD124;
		B2 = (tmp << 15) | (tmp >>> (32 - 15));
		tmp = A2 + (B2 ^ C2 ^ D2) + X[14] + 0x5C4DD124;
		A2 = (tmp << 6) | (tmp >>> (32 - 6));
		tmp = D2 + (A2 ^ B2 ^ C2) + X[7] + 0x5C4DD124;
		D2 = (tmp << 8) | (tmp >>> (32 - 8));
		tmp = C2 + (D2 ^ A2 ^ B2) + X[0] + 0x5C4DD124;
		C2 = (tmp << 13) | (tmp >>> (32 - 13));
		tmp = B2 + (C2 ^ D2 ^ A2) + X[6] + 0x5C4DD124;
		B2 = (tmp << 6) | (tmp >>> (32 - 6));
		tmp = A2 + (B2 ^ C2 ^ D2) + X[11] + 0x5C4DD124;
		A2 = (tmp << 12) | (tmp >>> (32 - 12));
		tmp = D2 + (A2 ^ B2 ^ C2) + X[13] + 0x5C4DD124;
		D2 = (tmp << 5) | (tmp >>> (32 - 5));
		tmp = C2 + (D2 ^ A2 ^ B2) + X[5] + 0x5C4DD124;
		C2 = (tmp << 7) | (tmp >>> (32 - 7));
		tmp = B2 + (C2 ^ D2 ^ A2) + X[12] + 0x5C4DD124;
		B2 = (tmp << 5) | (tmp >>> (32 - 5));

		int T = H1 + C1 + D2;
		currentVal[1] = H2 + D1 + A2;
		currentVal[2] = H3 + A1 + B2;
		currentVal[3] = H0 + B1 + C2;
		currentVal[0] = T;
	}

	/** @see Digest */
	public String toString()
	{
		return "RIPEMD";
	}
}
