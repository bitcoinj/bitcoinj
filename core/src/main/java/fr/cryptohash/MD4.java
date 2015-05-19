// $Id: MD4.java 241 2010-06-21 15:04:01Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the MD4 digest algorithm under the
 * {@link Digest} API, using the {@link DigestEngine} class.
 * MD4 is described in RFC 1320.</p>
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

public class MD4 extends MDHelper {

	/**
	 * Create the object.
	 */
	public MD4()
	{
		super(true, 8);
	}

	private int[] currentVal;

	/** @see Digest */
	public Digest copy()
	{
		MD4 d = new MD4();
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
		currentVal[0] = 0x67452301;
		currentVal[1] = 0xEFCDAB89;
		currentVal[2] = 0x98BADCFE;
		currentVal[3] = 0x10325476;
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		makeMDPadding();
		for (int i = 0; i < 4; i ++)
			encodeLEInt(currentVal[i], output,
				outputOffset + 4 * i);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		currentVal = new int[4];
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
	static private final void encodeLEInt(int val, byte[] buf, int off)
	{
		buf[off + 3] = (byte)((val >> 24) & 0xff);
		buf[off + 2] = (byte)((val >> 16) & 0xff);
		buf[off + 1] = (byte)((val >> 8) & 0xff);
		buf[off + 0] = (byte)(val & 0xff);
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		/*
		 * This method could have been made simpler by using
		 * external methods for 32-bit decoding, or the round
		 * functions F, G and H. However, it seems that the JIT
		 * compiler from Sun's JDK decides not to inline those
		 * methods, although it could (they are private final,
		 * hence cannot be overridden) and it would yield better
		 * performance.
		 */
		int A = currentVal[0], B = currentVal[1];
		int C = currentVal[2], D = currentVal[3];

		int X00 = (data[0] & 0xFF)
			| ((data[0 + 1] & 0xFF) << 8)
			| ((data[0 + 2] & 0xFF) << 16)
			| ((data[0 + 3] & 0xFF) << 24);
		int X01 = (data[4] & 0xFF)
			| ((data[4 + 1] & 0xFF) << 8)
			| ((data[4 + 2] & 0xFF) << 16)
			| ((data[4 + 3] & 0xFF) << 24);
		int X02 = (data[8] & 0xFF)
			| ((data[8 + 1] & 0xFF) << 8)
			| ((data[8 + 2] & 0xFF) << 16)
			| ((data[8 + 3] & 0xFF) << 24);
		int X03 = (data[12] & 0xFF)
			| ((data[12 + 1] & 0xFF) << 8)
			| ((data[12 + 2] & 0xFF) << 16)
			| ((data[12 + 3] & 0xFF) << 24);
		int X04 = (data[16] & 0xFF)
			| ((data[16 + 1] & 0xFF) << 8)
			| ((data[16 + 2] & 0xFF) << 16)
			| ((data[16 + 3] & 0xFF) << 24);
		int X05 = (data[20] & 0xFF)
			| ((data[20 + 1] & 0xFF) << 8)
			| ((data[20 + 2] & 0xFF) << 16)
			| ((data[20 + 3] & 0xFF) << 24);
		int X06 = (data[24] & 0xFF)
			| ((data[24 + 1] & 0xFF) << 8)
			| ((data[24 + 2] & 0xFF) << 16)
			| ((data[24 + 3] & 0xFF) << 24);
		int X07 = (data[28] & 0xFF)
			| ((data[28 + 1] & 0xFF) << 8)
			| ((data[28 + 2] & 0xFF) << 16)
			| ((data[28 + 3] & 0xFF) << 24);
		int X08 = (data[32] & 0xFF)
			| ((data[32 + 1] & 0xFF) << 8)
			| ((data[32 + 2] & 0xFF) << 16)
			| ((data[32 + 3] & 0xFF) << 24);
		int X09 = (data[36] & 0xFF)
			| ((data[36 + 1] & 0xFF) << 8)
			| ((data[36 + 2] & 0xFF) << 16)
			| ((data[36 + 3] & 0xFF) << 24);
		int X10 = (data[40] & 0xFF)
			| ((data[40 + 1] & 0xFF) << 8)
			| ((data[40 + 2] & 0xFF) << 16)
			| ((data[40 + 3] & 0xFF) << 24);
		int X11 = (data[44] & 0xFF)
			| ((data[44 + 1] & 0xFF) << 8)
			| ((data[44 + 2] & 0xFF) << 16)
			| ((data[44 + 3] & 0xFF) << 24);
		int X12 = (data[48] & 0xFF)
			| ((data[48 + 1] & 0xFF) << 8)
			| ((data[48 + 2] & 0xFF) << 16)
			| ((data[48 + 3] & 0xFF) << 24);
		int X13 = (data[52] & 0xFF)
			| ((data[52 + 1] & 0xFF) << 8)
			| ((data[52 + 2] & 0xFF) << 16)
			| ((data[52 + 3] & 0xFF) << 24);
		int X14 = (data[56] & 0xFF)
			| ((data[56 + 1] & 0xFF) << 8)
			| ((data[56 + 2] & 0xFF) << 16)
			| ((data[56 + 3] & 0xFF) << 24);
		int X15 = (data[60] & 0xFF)
			| ((data[60 + 1] & 0xFF) << 8)
			| ((data[60 + 2] & 0xFF) << 16)
			| ((data[60 + 3] & 0xFF) << 24);
		int T;

		T = A + (((C ^ D) & B) ^ D) + X00;
		A = (T << 3) | (T >>> (32 - 3));
		T = D + (((B ^ C) & A) ^ C) + X01;
		D = (T << 7) | (T >>> (32 - 7));
		T = C + (((A ^ B) & D) ^ B) + X02;
		C = (T << 11) | (T >>> (32 - 11));
		T = B + (((D ^ A) & C) ^ A) + X03;
		B = (T << 19) | (T >>> (32 - 19));
		T = A + (((C ^ D) & B) ^ D) + X04;
		A = (T << 3) | (T >>> (32 - 3));
		T = D + (((B ^ C) & A) ^ C) + X05;
		D = (T << 7) | (T >>> (32 - 7));
		T = C + (((A ^ B) & D) ^ B) + X06;
		C = (T << 11) | (T >>> (32 - 11));
		T = B + (((D ^ A) & C) ^ A) + X07;
		B = (T << 19) | (T >>> (32 - 19));
		T = A + (((C ^ D) & B) ^ D) + X08;
		A = (T << 3) | (T >>> (32 - 3));
		T = D + (((B ^ C) & A) ^ C) + X09;
		D = (T << 7) | (T >>> (32 - 7));
		T = C + (((A ^ B) & D) ^ B) + X10;
		C = (T << 11) | (T >>> (32 - 11));
		T = B + (((D ^ A) & C) ^ A) + X11;
		B = (T << 19) | (T >>> (32 - 19));
		T = A + (((C ^ D) & B) ^ D) + X12;
		A = (T << 3) | (T >>> (32 - 3));
		T = D + (((B ^ C) & A) ^ C) + X13;
		D = (T << 7) | (T >>> (32 - 7));
		T = C + (((A ^ B) & D) ^ B) + X14;
		C = (T << 11) | (T >>> (32 - 11));
		T = B + (((D ^ A) & C) ^ A) + X15;
		B = (T << 19) | (T >>> (32 - 19));

		T = A + ((D & C) | ((D | C) & B)) + X00 + 0x5A827999;
		A = (T << 3) | (T >>> (32 - 3));
		T = D + ((C & B) | ((C | B) & A)) + X04 + 0x5A827999;
		D = (T << 5) | (T >>> (32 - 5));
		T = C + ((B & A) | ((B | A) & D)) + X08 + 0x5A827999;
		C = (T << 9) | (T >>> (32 - 9));
		T = B + ((A & D) | ((A | D) & C)) + X12 + 0x5A827999;
		B = (T << 13) | (T >>> (32 - 13));
		T = A + ((D & C) | ((D | C) & B)) + X01 + 0x5A827999;
		A = (T << 3) | (T >>> (32 - 3));
		T = D + ((C & B) | ((C | B) & A)) + X05 + 0x5A827999;
		D = (T << 5) | (T >>> (32 - 5));
		T = C + ((B & A) | ((B | A) & D)) + X09 + 0x5A827999;
		C = (T << 9) | (T >>> (32 - 9));
		T = B + ((A & D) | ((A | D) & C)) + X13 + 0x5A827999;
		B = (T << 13) | (T >>> (32 - 13));
		T = A + ((D & C) | ((D | C) & B)) + X02 + 0x5A827999;
		A = (T << 3) | (T >>> (32 - 3));
		T = D + ((C & B) | ((C | B) & A)) + X06 + 0x5A827999;
		D = (T << 5) | (T >>> (32 - 5));
		T = C + ((B & A) | ((B | A) & D)) + X10 + 0x5A827999;
		C = (T << 9) | (T >>> (32 - 9));
		T = B + ((A & D) | ((A | D) & C)) + X14 + 0x5A827999;
		B = (T << 13) | (T >>> (32 - 13));
		T = A + ((D & C) | ((D | C) & B)) + X03 + 0x5A827999;
		A = (T << 3) | (T >>> (32 - 3));
		T = D + ((C & B) | ((C | B) & A)) + X07 + 0x5A827999;
		D = (T << 5) | (T >>> (32 - 5));
		T = C + ((B & A) | ((B | A) & D)) + X11 + 0x5A827999;
		C = (T << 9) | (T >>> (32 - 9));
		T = B + ((A & D) | ((A | D) & C)) + X15 + 0x5A827999;
		B = (T << 13) | (T >>> (32 - 13));

		T = A + (B ^ C ^ D) + X00 + 0x6ED9EBA1;
		A = (T << 3) | (T >>> (32 - 3));
		T = D + (A ^ B ^ C) + X08 + 0x6ED9EBA1;
		D = (T << 9) | (T >>> (32 - 9));
		T = C + (D ^ A ^ B) + X04 + 0x6ED9EBA1;
		C = (T << 11) | (T >>> (32 - 11));
		T = B + (C ^ D ^ A) + X12 + 0x6ED9EBA1;
		B = (T << 15) | (T >>> (32 - 15));
		T = A + (B ^ C ^ D) + X02 + 0x6ED9EBA1;
		A = (T << 3) | (T >>> (32 - 3));
		T = D + (A ^ B ^ C) + X10 + 0x6ED9EBA1;
		D = (T << 9) | (T >>> (32 - 9));
		T = C + (D ^ A ^ B) + X06 + 0x6ED9EBA1;
		C = (T << 11) | (T >>> (32 - 11));
		T = B + (C ^ D ^ A) + X14 + 0x6ED9EBA1;
		B = (T << 15) | (T >>> (32 - 15));
		T = A + (B ^ C ^ D) + X01 + 0x6ED9EBA1;
		A = (T << 3) | (T >>> (32 - 3));
		T = D + (A ^ B ^ C) + X09 + 0x6ED9EBA1;
		D = (T << 9) | (T >>> (32 - 9));
		T = C + (D ^ A ^ B) + X05 + 0x6ED9EBA1;
		C = (T << 11) | (T >>> (32 - 11));
		T = B + (C ^ D ^ A) + X13 + 0x6ED9EBA1;
		B = (T << 15) | (T >>> (32 - 15));
		T = A + (B ^ C ^ D) + X03 + 0x6ED9EBA1;
		A = (T << 3) | (T >>> (32 - 3));
		T = D + (A ^ B ^ C) + X11 + 0x6ED9EBA1;
		D = (T << 9) | (T >>> (32 - 9));
		T = C + (D ^ A ^ B) + X07 + 0x6ED9EBA1;
		C = (T << 11) | (T >>> (32 - 11));
		T = B + (C ^ D ^ A) + X15 + 0x6ED9EBA1;
		B = (T << 15) | (T >>> (32 - 15));

		currentVal[0] += A;
		currentVal[1] += B;
		currentVal[2] += C;
		currentVal[3] += D;
	}

	/** @see Digest */
	public String toString()
	{
		return "MD4";
	}
}
