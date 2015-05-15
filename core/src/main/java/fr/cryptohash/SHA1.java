// $Id: SHA1.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the SHA-1 digest algorithm under the
 * {@link Digest} API. SHA-1 is defined by FIPS 180-2.</p>
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

public class SHA1 extends MDHelper {

	/**
	 * Build the object.
	 */
	public SHA1()
	{
		super(false, 8);
	}

	private int[] currentVal;

	/** @see Digest */
	public Digest copy()
	{
		SHA1 d = new SHA1();
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
			encodeBEInt(currentVal[i],
				output, outputOffset + 4 * i);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		currentVal = new int[5];
		engineReset();
	}

	/**
	 * Encode the 32-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in big-endian
	 * convention (most significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	private static final void encodeBEInt(int val, byte[] buf, int off)
	{
		buf[off + 0] = (byte)(val >>> 24);
		buf[off + 1] = (byte)(val >>> 16);
		buf[off + 2] = (byte)(val >>> 8);
		buf[off + 3] = (byte)val;
	}

	/**
	 * Decode a 32-bit big-endian word from the array {@code buf}
	 * at offset {@code off}.
	 *
	 * @param buf   the source buffer
	 * @param off   the source offset
	 * @return  the decoded value
	 */
	private static final int decodeBEInt(byte[] buf, int off)
	{
		return ((buf[off] & 0xFF) << 24)
			| ((buf[off + 1] & 0xFF) << 16)
			| ((buf[off + 2] & 0xFF) << 8)
			| (buf[off + 3] & 0xFF);
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		int A = currentVal[0], B = currentVal[1];
		int C = currentVal[2], D = currentVal[3], E = currentVal[4];
		int U;

		int W0 = decodeBEInt(data, 0);
		E = ((A << 5) | (A >>> 27)) + ((B & C) | (~B & D))
			 + E + W0 + 0x5A827999;
		B = (B << 30) | (B >>> 2);
		int W1 = decodeBEInt(data, 4);
		D = ((E << 5) | (E >>> 27)) + ((A & B) | (~A & C))
			 + D + W1 + 0x5A827999;
		A = (A << 30) | (A >>> 2);
		int W2 = decodeBEInt(data, 8);
		C = ((D << 5) | (D >>> 27)) + ((E & A) | (~E & B))
			 + C + W2 + 0x5A827999;
		E = (E << 30) | (E >>> 2);
		int W3 = decodeBEInt(data, 12);
		B = ((C << 5) | (C >>> 27)) + ((D & E) | (~D & A))
			 + B + W3 + 0x5A827999;
		D = (D << 30) | (D >>> 2);
		int W4 = decodeBEInt(data, 16);
		A = ((B << 5) | (B >>> 27)) + ((C & D) | (~C & E))
			 + A + W4 + 0x5A827999;
		C = (C << 30) | (C >>> 2);
		int W5 = decodeBEInt(data, 20);
		E = ((A << 5) | (A >>> 27)) + ((B & C) | (~B & D))
			 + E + W5 + 0x5A827999;
		B = (B << 30) | (B >>> 2);
		int W6 = decodeBEInt(data, 24);
		D = ((E << 5) | (E >>> 27)) + ((A & B) | (~A & C))
			 + D + W6 + 0x5A827999;
		A = (A << 30) | (A >>> 2);
		int W7 = decodeBEInt(data, 28);
		C = ((D << 5) | (D >>> 27)) + ((E & A) | (~E & B))
			 + C + W7 + 0x5A827999;
		E = (E << 30) | (E >>> 2);
		int W8 = decodeBEInt(data, 32);
		B = ((C << 5) | (C >>> 27)) + ((D & E) | (~D & A))
			 + B + W8 + 0x5A827999;
		D = (D << 30) | (D >>> 2);
		int W9 = decodeBEInt(data, 36);
		A = ((B << 5) | (B >>> 27)) + ((C & D) | (~C & E))
			 + A + W9 + 0x5A827999;
		C = (C << 30) | (C >>> 2);
		int Wa = decodeBEInt(data, 40);
		E = ((A << 5) | (A >>> 27)) + ((B & C) | (~B & D))
			 + E + Wa + 0x5A827999;
		B = (B << 30) | (B >>> 2);
		int Wb = decodeBEInt(data, 44);
		D = ((E << 5) | (E >>> 27)) + ((A & B) | (~A & C))
			 + D + Wb + 0x5A827999;
		A = (A << 30) | (A >>> 2);
		int Wc = decodeBEInt(data, 48);
		C = ((D << 5) | (D >>> 27)) + ((E & A) | (~E & B))
			 + C + Wc + 0x5A827999;
		E = (E << 30) | (E >>> 2);
		int Wd = decodeBEInt(data, 52);
		B = ((C << 5) | (C >>> 27)) + ((D & E) | (~D & A))
			 + B + Wd + 0x5A827999;
		D = (D << 30) | (D >>> 2);
		int We = decodeBEInt(data, 56);
		A = ((B << 5) | (B >>> 27)) + ((C & D) | (~C & E))
			 + A + We + 0x5A827999;
		C = (C << 30) | (C >>> 2);
		int Wf = decodeBEInt(data, 60);
		E = ((A << 5) | (A >>> 27)) + ((B & C) | (~B & D))
			 + E + Wf + 0x5A827999;
		B = (B << 30) | (B >>> 2);
		U = Wd ^ W8 ^ W2 ^ W0;
		W0 = (U << 1) | (U >>> 31);
		D = ((E << 5) | (E >>> 27)) + ((A & B) | (~A & C))
			 + D + W0 + 0x5A827999;
		A = (A << 30) | (A >>> 2);
		U = We ^ W9 ^ W3 ^ W1;
		W1 = (U << 1) | (U >>> 31);
		C = ((D << 5) | (D >>> 27)) + ((E & A) | (~E & B))
			 + C + W1 + 0x5A827999;
		E = (E << 30) | (E >>> 2);
		U = Wf ^ Wa ^ W4 ^ W2;
		W2 = (U << 1) | (U >>> 31);
		B = ((C << 5) | (C >>> 27)) + ((D & E) | (~D & A))
			 + B + W2 + 0x5A827999;
		D = (D << 30) | (D >>> 2);
		U = W0 ^ Wb ^ W5 ^ W3;
		W3 = (U << 1) | (U >>> 31);
		A = ((B << 5) | (B >>> 27)) + ((C & D) | (~C & E))
			 + A + W3 + 0x5A827999;
		C = (C << 30) | (C >>> 2);
		U = W1 ^ Wc ^ W6 ^ W4;
		W4 = (U << 1) | (U >>> 31);
		E = ((A << 5) | (A >>> 27)) + (B ^ C ^ D)
			 + E + W4 + 0x6ED9EBA1;
		B = (B << 30) | (B >>> 2);
		U = W2 ^ Wd ^ W7 ^ W5;
		W5 = (U << 1) | (U >>> 31);
		D = ((E << 5) | (E >>> 27)) + (A ^ B ^ C)
			 + D + W5 + 0x6ED9EBA1;
		A = (A << 30) | (A >>> 2);
		U = W3 ^ We ^ W8 ^ W6;
		W6 = (U << 1) | (U >>> 31);
		C = ((D << 5) | (D >>> 27)) + (E ^ A ^ B)
			 + C + W6 + 0x6ED9EBA1;
		E = (E << 30) | (E >>> 2);
		U = W4 ^ Wf ^ W9 ^ W7;
		W7 = (U << 1) | (U >>> 31);
		B = ((C << 5) | (C >>> 27)) + (D ^ E ^ A)
			 + B + W7 + 0x6ED9EBA1;
		D = (D << 30) | (D >>> 2);
		U = W5 ^ W0 ^ Wa ^ W8;
		W8 = (U << 1) | (U >>> 31);
		A = ((B << 5) | (B >>> 27)) + (C ^ D ^ E)
			 + A + W8 + 0x6ED9EBA1;
		C = (C << 30) | (C >>> 2);
		U = W6 ^ W1 ^ Wb ^ W9;
		W9 = (U << 1) | (U >>> 31);
		E = ((A << 5) | (A >>> 27)) + (B ^ C ^ D)
			 + E + W9 + 0x6ED9EBA1;
		B = (B << 30) | (B >>> 2);
		U = W7 ^ W2 ^ Wc ^ Wa;
		Wa = (U << 1) | (U >>> 31);
		D = ((E << 5) | (E >>> 27)) + (A ^ B ^ C)
			 + D + Wa + 0x6ED9EBA1;
		A = (A << 30) | (A >>> 2);
		U = W8 ^ W3 ^ Wd ^ Wb;
		Wb = (U << 1) | (U >>> 31);
		C = ((D << 5) | (D >>> 27)) + (E ^ A ^ B)
			 + C + Wb + 0x6ED9EBA1;
		E = (E << 30) | (E >>> 2);
		U = W9 ^ W4 ^ We ^ Wc;
		Wc = (U << 1) | (U >>> 31);
		B = ((C << 5) | (C >>> 27)) + (D ^ E ^ A)
			 + B + Wc + 0x6ED9EBA1;
		D = (D << 30) | (D >>> 2);
		U = Wa ^ W5 ^ Wf ^ Wd;
		Wd = (U << 1) | (U >>> 31);
		A = ((B << 5) | (B >>> 27)) + (C ^ D ^ E)
			 + A + Wd + 0x6ED9EBA1;
		C = (C << 30) | (C >>> 2);
		U = Wb ^ W6 ^ W0 ^ We;
		We = (U << 1) | (U >>> 31);
		E = ((A << 5) | (A >>> 27)) + (B ^ C ^ D)
			 + E + We + 0x6ED9EBA1;
		B = (B << 30) | (B >>> 2);
		U = Wc ^ W7 ^ W1 ^ Wf;
		Wf = (U << 1) | (U >>> 31);
		D = ((E << 5) | (E >>> 27)) + (A ^ B ^ C)
			 + D + Wf + 0x6ED9EBA1;
		A = (A << 30) | (A >>> 2);
		U = Wd ^ W8 ^ W2 ^ W0;
		W0 = (U << 1) | (U >>> 31);
		C = ((D << 5) | (D >>> 27)) + (E ^ A ^ B)
			 + C + W0 + 0x6ED9EBA1;
		E = (E << 30) | (E >>> 2);
		U = We ^ W9 ^ W3 ^ W1;
		W1 = (U << 1) | (U >>> 31);
		B = ((C << 5) | (C >>> 27)) + (D ^ E ^ A)
			 + B + W1 + 0x6ED9EBA1;
		D = (D << 30) | (D >>> 2);
		U = Wf ^ Wa ^ W4 ^ W2;
		W2 = (U << 1) | (U >>> 31);
		A = ((B << 5) | (B >>> 27)) + (C ^ D ^ E)
			 + A + W2 + 0x6ED9EBA1;
		C = (C << 30) | (C >>> 2);
		U = W0 ^ Wb ^ W5 ^ W3;
		W3 = (U << 1) | (U >>> 31);
		E = ((A << 5) | (A >>> 27)) + (B ^ C ^ D)
			 + E + W3 + 0x6ED9EBA1;
		B = (B << 30) | (B >>> 2);
		U = W1 ^ Wc ^ W6 ^ W4;
		W4 = (U << 1) | (U >>> 31);
		D = ((E << 5) | (E >>> 27)) + (A ^ B ^ C)
			 + D + W4 + 0x6ED9EBA1;
		A = (A << 30) | (A >>> 2);
		U = W2 ^ Wd ^ W7 ^ W5;
		W5 = (U << 1) | (U >>> 31);
		C = ((D << 5) | (D >>> 27)) + (E ^ A ^ B)
			 + C + W5 + 0x6ED9EBA1;
		E = (E << 30) | (E >>> 2);
		U = W3 ^ We ^ W8 ^ W6;
		W6 = (U << 1) | (U >>> 31);
		B = ((C << 5) | (C >>> 27)) + (D ^ E ^ A)
			 + B + W6 + 0x6ED9EBA1;
		D = (D << 30) | (D >>> 2);
		U = W4 ^ Wf ^ W9 ^ W7;
		W7 = (U << 1) | (U >>> 31);
		A = ((B << 5) | (B >>> 27)) + (C ^ D ^ E)
			 + A + W7 + 0x6ED9EBA1;
		C = (C << 30) | (C >>> 2);
		U = W5 ^ W0 ^ Wa ^ W8;
		W8 = (U << 1) | (U >>> 31);
		E = ((A << 5) | (A >>> 27)) + ((B & C) | (B & D) | (C & D))
			 + E + W8 + 0x8F1BBCDC;
		B = (B << 30) | (B >>> 2);
		U = W6 ^ W1 ^ Wb ^ W9;
		W9 = (U << 1) | (U >>> 31);
		D = ((E << 5) | (E >>> 27)) + ((A & B) | (A & C) | (B & C))
			 + D + W9 + 0x8F1BBCDC;
		A = (A << 30) | (A >>> 2);
		U = W7 ^ W2 ^ Wc ^ Wa;
		Wa = (U << 1) | (U >>> 31);
		C = ((D << 5) | (D >>> 27)) + ((E & A) | (E & B) | (A & B))
			 + C + Wa + 0x8F1BBCDC;
		E = (E << 30) | (E >>> 2);
		U = W8 ^ W3 ^ Wd ^ Wb;
		Wb = (U << 1) | (U >>> 31);
		B = ((C << 5) | (C >>> 27)) + ((D & E) | (D & A) | (E & A))
			 + B + Wb + 0x8F1BBCDC;
		D = (D << 30) | (D >>> 2);
		U = W9 ^ W4 ^ We ^ Wc;
		Wc = (U << 1) | (U >>> 31);
		A = ((B << 5) | (B >>> 27)) + ((C & D) | (C & E) | (D & E))
			 + A + Wc + 0x8F1BBCDC;
		C = (C << 30) | (C >>> 2);
		U = Wa ^ W5 ^ Wf ^ Wd;
		Wd = (U << 1) | (U >>> 31);
		E = ((A << 5) | (A >>> 27)) + ((B & C) | (B & D) | (C & D))
			 + E + Wd + 0x8F1BBCDC;
		B = (B << 30) | (B >>> 2);
		U = Wb ^ W6 ^ W0 ^ We;
		We = (U << 1) | (U >>> 31);
		D = ((E << 5) | (E >>> 27)) + ((A & B) | (A & C) | (B & C))
			 + D + We + 0x8F1BBCDC;
		A = (A << 30) | (A >>> 2);
		U = Wc ^ W7 ^ W1 ^ Wf;
		Wf = (U << 1) | (U >>> 31);
		C = ((D << 5) | (D >>> 27)) + ((E & A) | (E & B) | (A & B))
			 + C + Wf + 0x8F1BBCDC;
		E = (E << 30) | (E >>> 2);
		U = Wd ^ W8 ^ W2 ^ W0;
		W0 = (U << 1) | (U >>> 31);
		B = ((C << 5) | (C >>> 27)) + ((D & E) | (D & A) | (E & A))
			 + B + W0 + 0x8F1BBCDC;
		D = (D << 30) | (D >>> 2);
		U = We ^ W9 ^ W3 ^ W1;
		W1 = (U << 1) | (U >>> 31);
		A = ((B << 5) | (B >>> 27)) + ((C & D) | (C & E) | (D & E))
			 + A + W1 + 0x8F1BBCDC;
		C = (C << 30) | (C >>> 2);
		U = Wf ^ Wa ^ W4 ^ W2;
		W2 = (U << 1) | (U >>> 31);
		E = ((A << 5) | (A >>> 27)) + ((B & C) | (B & D) | (C & D))
			 + E + W2 + 0x8F1BBCDC;
		B = (B << 30) | (B >>> 2);
		U = W0 ^ Wb ^ W5 ^ W3;
		W3 = (U << 1) | (U >>> 31);
		D = ((E << 5) | (E >>> 27)) + ((A & B) | (A & C) | (B & C))
			 + D + W3 + 0x8F1BBCDC;
		A = (A << 30) | (A >>> 2);
		U = W1 ^ Wc ^ W6 ^ W4;
		W4 = (U << 1) | (U >>> 31);
		C = ((D << 5) | (D >>> 27)) + ((E & A) | (E & B) | (A & B))
			 + C + W4 + 0x8F1BBCDC;
		E = (E << 30) | (E >>> 2);
		U = W2 ^ Wd ^ W7 ^ W5;
		W5 = (U << 1) | (U >>> 31);
		B = ((C << 5) | (C >>> 27)) + ((D & E) | (D & A) | (E & A))
			 + B + W5 + 0x8F1BBCDC;
		D = (D << 30) | (D >>> 2);
		U = W3 ^ We ^ W8 ^ W6;
		W6 = (U << 1) | (U >>> 31);
		A = ((B << 5) | (B >>> 27)) + ((C & D) | (C & E) | (D & E))
			 + A + W6 + 0x8F1BBCDC;
		C = (C << 30) | (C >>> 2);
		U = W4 ^ Wf ^ W9 ^ W7;
		W7 = (U << 1) | (U >>> 31);
		E = ((A << 5) | (A >>> 27)) + ((B & C) | (B & D) | (C & D))
			 + E + W7 + 0x8F1BBCDC;
		B = (B << 30) | (B >>> 2);
		U = W5 ^ W0 ^ Wa ^ W8;
		W8 = (U << 1) | (U >>> 31);
		D = ((E << 5) | (E >>> 27)) + ((A & B) | (A & C) | (B & C))
			 + D + W8 + 0x8F1BBCDC;
		A = (A << 30) | (A >>> 2);
		U = W6 ^ W1 ^ Wb ^ W9;
		W9 = (U << 1) | (U >>> 31);
		C = ((D << 5) | (D >>> 27)) + ((E & A) | (E & B) | (A & B))
			 + C + W9 + 0x8F1BBCDC;
		E = (E << 30) | (E >>> 2);
		U = W7 ^ W2 ^ Wc ^ Wa;
		Wa = (U << 1) | (U >>> 31);
		B = ((C << 5) | (C >>> 27)) + ((D & E) | (D & A) | (E & A))
			 + B + Wa + 0x8F1BBCDC;
		D = (D << 30) | (D >>> 2);
		U = W8 ^ W3 ^ Wd ^ Wb;
		Wb = (U << 1) | (U >>> 31);
		A = ((B << 5) | (B >>> 27)) + ((C & D) | (C & E) | (D & E))
			 + A + Wb + 0x8F1BBCDC;
		C = (C << 30) | (C >>> 2);
		U = W9 ^ W4 ^ We ^ Wc;
		Wc = (U << 1) | (U >>> 31);
		E = ((A << 5) | (A >>> 27)) + (B ^ C ^ D)
			 + E + Wc + 0xCA62C1D6;
		B = (B << 30) | (B >>> 2);
		U = Wa ^ W5 ^ Wf ^ Wd;
		Wd = (U << 1) | (U >>> 31);
		D = ((E << 5) | (E >>> 27)) + (A ^ B ^ C)
			 + D + Wd + 0xCA62C1D6;
		A = (A << 30) | (A >>> 2);
		U = Wb ^ W6 ^ W0 ^ We;
		We = (U << 1) | (U >>> 31);
		C = ((D << 5) | (D >>> 27)) + (E ^ A ^ B)
			 + C + We + 0xCA62C1D6;
		E = (E << 30) | (E >>> 2);
		U = Wc ^ W7 ^ W1 ^ Wf;
		Wf = (U << 1) | (U >>> 31);
		B = ((C << 5) | (C >>> 27)) + (D ^ E ^ A)
			 + B + Wf + 0xCA62C1D6;
		D = (D << 30) | (D >>> 2);
		U = Wd ^ W8 ^ W2 ^ W0;
		W0 = (U << 1) | (U >>> 31);
		A = ((B << 5) | (B >>> 27)) + (C ^ D ^ E)
			 + A + W0 + 0xCA62C1D6;
		C = (C << 30) | (C >>> 2);
		U = We ^ W9 ^ W3 ^ W1;
		W1 = (U << 1) | (U >>> 31);
		E = ((A << 5) | (A >>> 27)) + (B ^ C ^ D)
			 + E + W1 + 0xCA62C1D6;
		B = (B << 30) | (B >>> 2);
		U = Wf ^ Wa ^ W4 ^ W2;
		W2 = (U << 1) | (U >>> 31);
		D = ((E << 5) | (E >>> 27)) + (A ^ B ^ C)
			 + D + W2 + 0xCA62C1D6;
		A = (A << 30) | (A >>> 2);
		U = W0 ^ Wb ^ W5 ^ W3;
		W3 = (U << 1) | (U >>> 31);
		C = ((D << 5) | (D >>> 27)) + (E ^ A ^ B)
			 + C + W3 + 0xCA62C1D6;
		E = (E << 30) | (E >>> 2);
		U = W1 ^ Wc ^ W6 ^ W4;
		W4 = (U << 1) | (U >>> 31);
		B = ((C << 5) | (C >>> 27)) + (D ^ E ^ A)
			 + B + W4 + 0xCA62C1D6;
		D = (D << 30) | (D >>> 2);
		U = W2 ^ Wd ^ W7 ^ W5;
		W5 = (U << 1) | (U >>> 31);
		A = ((B << 5) | (B >>> 27)) + (C ^ D ^ E)
			 + A + W5 + 0xCA62C1D6;
		C = (C << 30) | (C >>> 2);
		U = W3 ^ We ^ W8 ^ W6;
		W6 = (U << 1) | (U >>> 31);
		E = ((A << 5) | (A >>> 27)) + (B ^ C ^ D)
			 + E + W6 + 0xCA62C1D6;
		B = (B << 30) | (B >>> 2);
		U = W4 ^ Wf ^ W9 ^ W7;
		W7 = (U << 1) | (U >>> 31);
		D = ((E << 5) | (E >>> 27)) + (A ^ B ^ C)
			 + D + W7 + 0xCA62C1D6;
		A = (A << 30) | (A >>> 2);
		U = W5 ^ W0 ^ Wa ^ W8;
		W8 = (U << 1) | (U >>> 31);
		C = ((D << 5) | (D >>> 27)) + (E ^ A ^ B)
			 + C + W8 + 0xCA62C1D6;
		E = (E << 30) | (E >>> 2);
		U = W6 ^ W1 ^ Wb ^ W9;
		W9 = (U << 1) | (U >>> 31);
		B = ((C << 5) | (C >>> 27)) + (D ^ E ^ A)
			 + B + W9 + 0xCA62C1D6;
		D = (D << 30) | (D >>> 2);
		U = W7 ^ W2 ^ Wc ^ Wa;
		Wa = (U << 1) | (U >>> 31);
		A = ((B << 5) | (B >>> 27)) + (C ^ D ^ E)
			 + A + Wa + 0xCA62C1D6;
		C = (C << 30) | (C >>> 2);
		U = W8 ^ W3 ^ Wd ^ Wb;
		Wb = (U << 1) | (U >>> 31);
		E = ((A << 5) | (A >>> 27)) + (B ^ C ^ D)
			 + E + Wb + 0xCA62C1D6;
		B = (B << 30) | (B >>> 2);
		U = W9 ^ W4 ^ We ^ Wc;
		Wc = (U << 1) | (U >>> 31);
		D = ((E << 5) | (E >>> 27)) + (A ^ B ^ C)
			 + D + Wc + 0xCA62C1D6;
		A = (A << 30) | (A >>> 2);
		U = Wa ^ W5 ^ Wf ^ Wd;
		Wd = (U << 1) | (U >>> 31);
		C = ((D << 5) | (D >>> 27)) + (E ^ A ^ B)
			 + C + Wd + 0xCA62C1D6;
		E = (E << 30) | (E >>> 2);
		U = Wb ^ W6 ^ W0 ^ We;
		We = (U << 1) | (U >>> 31);
		B = ((C << 5) | (C >>> 27)) + (D ^ E ^ A)
			 + B + We + 0xCA62C1D6;
		D = (D << 30) | (D >>> 2);
		U = Wc ^ W7 ^ W1 ^ Wf;
		Wf = (U << 1) | (U >>> 31);
		A = ((B << 5) | (B >>> 27)) + (C ^ D ^ E)
			 + A + Wf + 0xCA62C1D6;
		C = (C << 30) | (C >>> 2);

		currentVal[0] += A;
		currentVal[1] += B;
		currentVal[2] += C;
		currentVal[3] += D;
		currentVal[4] += E;
	}

	/** @see Digest */
	public String toString()
	{
		return "SHA-1";
	}
}
