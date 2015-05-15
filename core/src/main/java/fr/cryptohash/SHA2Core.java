// $Id: SHA2Core.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * This class implements SHA-224 and SHA-256, which differ only by the IV
 * and the output length.
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

abstract class SHA2Core extends MDHelper {

	/**
	 * Create the object.
	 */
	SHA2Core()
	{
		super(false, 8);
	}

	/** private special values. */
	private static final int[] K = {
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
		0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
		0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
		0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
		0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
		0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
		0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
		0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
		0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	};

	private int[] currentVal, W;

	/** @see DigestEngine */
	protected Digest copyState(SHA2Core dst)
	{
		System.arraycopy(currentVal, 0, dst.currentVal, 0,
			currentVal.length);
		return super.copyState(dst);
	}

	/** @see Digest */
	public int getBlockLength()
	{
		return 64;
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		System.arraycopy(getInitVal(), 0, currentVal, 0, 8);
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
		makeMDPadding();
		int olen = getDigestLength();
		for (int i = 0, j = 0; j < olen; i ++, j += 4)
			encodeBEInt(currentVal[i], output, outputOffset + j);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		currentVal = new int[8];
		W = new int[64];
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
		return (x << n) | (x >>> (32 - n));
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		int A = currentVal[0];
		int B = currentVal[1];
		int C = currentVal[2];
		int D = currentVal[3];
		int E = currentVal[4];
		int F = currentVal[5];
		int G = currentVal[6];
		int H = currentVal[7];

		for (int i = 0; i < 16; i ++)
			W[i] = decodeBEInt(data, 4 * i);
		for (int i = 16; i < 64; i ++) {
			W[i] = (circularLeft(W[i - 2], 15)
				^ circularLeft(W[i - 2], 13)
				^ (W[i - 2] >>> 10))
				+ W[i - 7]
				+ (circularLeft(W[i - 15], 25)
				^ circularLeft(W[i - 15], 14)
				^ (W[i - 15] >>> 3))
				+ W[i - 16];
		}
		for (int i = 0; i < 64; i ++) {
			int T1 = H + (circularLeft(E, 26) ^ circularLeft(E, 21)
				^ circularLeft(E, 7)) + ((F & E) ^ (G & ~E))
				+ K[i] + W[i];
			int T2 = (circularLeft(A, 30) ^ circularLeft(A, 19)
				^ circularLeft(A, 10))
				+ ((A & B) ^ (A & C) ^ (B & C));
			H = G; G = F; F = E; E = D + T1;
			D = C; C = B; B = A; A = T1 + T2;
		}
		currentVal[0] += A;
		currentVal[1] += B;
		currentVal[2] += C;
		currentVal[3] += D;
		currentVal[4] += E;
		currentVal[5] += F;
		currentVal[6] += G;
		currentVal[7] += H;

		/*
		 * The version below unrolls 16 rounds and inlines
		 * rotations. It should avoid many array accesses
		 * (W[] is transformed into 16 local variables) and
		 * data routing (16 is a multiple of 8, so the
		 * big rotation of the eight words becomes trivial).
		 * Strangely enough, it yields only a very small
		 * performance gain (less than 10% on Intel x86 with
		 * Sun JDK 6, both in 32-bit and 64-bit modes). Since
		 * it also probably consumes much more L1 cache, the
		 * simpler version above is preferred.
		 *
		int A = currentVal[0];
		int B = currentVal[1];
		int C = currentVal[2];
		int D = currentVal[3];
		int E = currentVal[4];
		int F = currentVal[5];
		int G = currentVal[6];
		int H = currentVal[7];
		int t1, t2;
		int pcount = 0;
		int W0 = decodeBEInt(data, 4 * 0x0);
		t1 = H + (((E >>> 6) | (E << (32 - 6))) ^ ((E >>> 11)
			| (E << (32 - 11))) ^ ((E >>> 25) | (E << (32 - 25))))
			+ (((F ^ G) & E) ^ G) + K[pcount + 0x0] + W0;
		t2 = (((A >>> 2) | (A << (32 - 2))) ^ ((A >>> 13)
			| (A << (32 - 13))) ^ ((A >>> 22) | (A << (32 - 22))))
			+ ((B & C) | ((B | C) & A));
		D += t1;
		H = t1 + t2;
		int W1 = decodeBEInt(data, 4 * 0x1);
		t1 = G + (((D >>> 6) | (D << (32 - 6))) ^ ((D >>> 11)
			| (D << (32 - 11))) ^ ((D >>> 25) | (D << (32 - 25))))
			+ (((E ^ F) & D) ^ F) + K[pcount + 0x1] + W1;
		t2 = (((H >>> 2) | (H << (32 - 2))) ^ ((H >>> 13)
			| (H << (32 - 13))) ^ ((H >>> 22) | (H << (32 - 22))))
			+ ((A & B) | ((A | B) & H));
		C += t1;
		G = t1 + t2;
		int W2 = decodeBEInt(data, 4 * 0x2);
		t1 = F + (((C >>> 6) | (C << (32 - 6))) ^ ((C >>> 11)
			| (C << (32 - 11))) ^ ((C >>> 25) | (C << (32 - 25))))
			+ (((D ^ E) & C) ^ E) + K[pcount + 0x2] + W2;
		t2 = (((G >>> 2) | (G << (32 - 2))) ^ ((G >>> 13)
			| (G << (32 - 13))) ^ ((G >>> 22) | (G << (32 - 22))))
			+ ((H & A) | ((H | A) & G));
		B += t1;
		F = t1 + t2;
		int W3 = decodeBEInt(data, 4 * 0x3);
		t1 = E + (((B >>> 6) | (B << (32 - 6))) ^ ((B >>> 11)
			| (B << (32 - 11))) ^ ((B >>> 25) | (B << (32 - 25))))
			+ (((C ^ D) & B) ^ D) + K[pcount + 0x3] + W3;
		t2 = (((F >>> 2) | (F << (32 - 2))) ^ ((F >>> 13)
			| (F << (32 - 13))) ^ ((F >>> 22) | (F << (32 - 22))))
			+ ((G & H) | ((G | H) & F));
		A += t1;
		E = t1 + t2;
		int W4 = decodeBEInt(data, 4 * 0x4);
		t1 = D + (((A >>> 6) | (A << (32 - 6))) ^ ((A >>> 11)
			| (A << (32 - 11))) ^ ((A >>> 25) | (A << (32 - 25))))
			+ (((B ^ C) & A) ^ C) + K[pcount + 0x4] + W4;
		t2 = (((E >>> 2) | (E << (32 - 2))) ^ ((E >>> 13)
			| (E << (32 - 13))) ^ ((E >>> 22) | (E << (32 - 22))))
			+ ((F & G) | ((F | G) & E));
		H += t1;
		D = t1 + t2;
		int W5 = decodeBEInt(data, 4 * 0x5);
		t1 = C + (((H >>> 6) | (H << (32 - 6))) ^ ((H >>> 11)
			| (H << (32 - 11))) ^ ((H >>> 25) | (H << (32 - 25))))
			+ (((A ^ B) & H) ^ B) + K[pcount + 0x5] + W5;
		t2 = (((D >>> 2) | (D << (32 - 2))) ^ ((D >>> 13)
			| (D << (32 - 13))) ^ ((D >>> 22) | (D << (32 - 22))))
			+ ((E & F) | ((E | F) & D));
		G += t1;
		C = t1 + t2;
		int W6 = decodeBEInt(data, 4 * 0x6);
		t1 = B + (((G >>> 6) | (G << (32 - 6))) ^ ((G >>> 11)
			| (G << (32 - 11))) ^ ((G >>> 25) | (G << (32 - 25))))
			+ (((H ^ A) & G) ^ A) + K[pcount + 0x6] + W6;
		t2 = (((C >>> 2) | (C << (32 - 2))) ^ ((C >>> 13)
			| (C << (32 - 13))) ^ ((C >>> 22) | (C << (32 - 22))))
			+ ((D & E) | ((D | E) & C));
		F += t1;
		B = t1 + t2;
		int W7 = decodeBEInt(data, 4 * 0x7);
		t1 = A + (((F >>> 6) | (F << (32 - 6))) ^ ((F >>> 11)
			| (F << (32 - 11))) ^ ((F >>> 25) | (F << (32 - 25))))
			+ (((G ^ H) & F) ^ H) + K[pcount + 0x7] + W7;
		t2 = (((B >>> 2) | (B << (32 - 2))) ^ ((B >>> 13)
			| (B << (32 - 13))) ^ ((B >>> 22) | (B << (32 - 22))))
			+ ((C & D) | ((C | D) & B));
		E += t1;
		A = t1 + t2;
		int W8 = decodeBEInt(data, 4 * 0x8);
		t1 = H + (((E >>> 6) | (E << (32 - 6))) ^ ((E >>> 11)
			| (E << (32 - 11))) ^ ((E >>> 25) | (E << (32 - 25))))
			+ (((F ^ G) & E) ^ G) + K[pcount + 0x8] + W8;
		t2 = (((A >>> 2) | (A << (32 - 2))) ^ ((A >>> 13)
			| (A << (32 - 13))) ^ ((A >>> 22) | (A << (32 - 22))))
			+ ((B & C) | ((B | C) & A));
		D += t1;
		H = t1 + t2;
		int W9 = decodeBEInt(data, 4 * 0x9);
		t1 = G + (((D >>> 6) | (D << (32 - 6))) ^ ((D >>> 11)
			| (D << (32 - 11))) ^ ((D >>> 25) | (D << (32 - 25))))
			+ (((E ^ F) & D) ^ F) + K[pcount + 0x9] + W9;
		t2 = (((H >>> 2) | (H << (32 - 2))) ^ ((H >>> 13)
			| (H << (32 - 13))) ^ ((H >>> 22) | (H << (32 - 22))))
			+ ((A & B) | ((A | B) & H));
		C += t1;
		G = t1 + t2;
		int WA = decodeBEInt(data, 4 * 0xA);
		t1 = F + (((C >>> 6) | (C << (32 - 6))) ^ ((C >>> 11)
			| (C << (32 - 11))) ^ ((C >>> 25) | (C << (32 - 25))))
			+ (((D ^ E) & C) ^ E) + K[pcount + 0xA] + WA;
		t2 = (((G >>> 2) | (G << (32 - 2))) ^ ((G >>> 13)
			| (G << (32 - 13))) ^ ((G >>> 22) | (G << (32 - 22))))
			+ ((H & A) | ((H | A) & G));
		B += t1;
		F = t1 + t2;
		int WB = decodeBEInt(data, 4 * 0xB);
		t1 = E + (((B >>> 6) | (B << (32 - 6))) ^ ((B >>> 11)
			| (B << (32 - 11))) ^ ((B >>> 25) | (B << (32 - 25))))
			+ (((C ^ D) & B) ^ D) + K[pcount + 0xB] + WB;
		t2 = (((F >>> 2) | (F << (32 - 2))) ^ ((F >>> 13)
			| (F << (32 - 13))) ^ ((F >>> 22) | (F << (32 - 22))))
			+ ((G & H) | ((G | H) & F));
		A += t1;
		E = t1 + t2;
		int WC = decodeBEInt(data, 4 * 0xC);
		t1 = D + (((A >>> 6) | (A << (32 - 6))) ^ ((A >>> 11)
			| (A << (32 - 11))) ^ ((A >>> 25) | (A << (32 - 25))))
			+ (((B ^ C) & A) ^ C) + K[pcount + 0xC] + WC;
		t2 = (((E >>> 2) | (E << (32 - 2))) ^ ((E >>> 13)
			| (E << (32 - 13))) ^ ((E >>> 22) | (E << (32 - 22))))
			+ ((F & G) | ((F | G) & E));
		H += t1;
		D = t1 + t2;
		int WD = decodeBEInt(data, 4 * 0xD);
		t1 = C + (((H >>> 6) | (H << (32 - 6))) ^ ((H >>> 11)
			| (H << (32 - 11))) ^ ((H >>> 25) | (H << (32 - 25))))
			+ (((A ^ B) & H) ^ B) + K[pcount + 0xD] + WD;
		t2 = (((D >>> 2) | (D << (32 - 2))) ^ ((D >>> 13)
			| (D << (32 - 13))) ^ ((D >>> 22) | (D << (32 - 22))))
			+ ((E & F) | ((E | F) & D));
		G += t1;
		C = t1 + t2;
		int WE = decodeBEInt(data, 4 * 0xE);
		t1 = B + (((G >>> 6) | (G << (32 - 6))) ^ ((G >>> 11)
			| (G << (32 - 11))) ^ ((G >>> 25) | (G << (32 - 25))))
			+ (((H ^ A) & G) ^ A) + K[pcount + 0xE] + WE;
		t2 = (((C >>> 2) | (C << (32 - 2))) ^ ((C >>> 13)
			| (C << (32 - 13))) ^ ((C >>> 22) | (C << (32 - 22))))
			+ ((D & E) | ((D | E) & C));
		F += t1;
		B = t1 + t2;
		int WF = decodeBEInt(data, 4 * 0xF);
		t1 = A + (((F >>> 6) | (F << (32 - 6))) ^ ((F >>> 11)
			| (F << (32 - 11))) ^ ((F >>> 25) | (F << (32 - 25))))
			+ (((G ^ H) & F) ^ H) + K[pcount + 0xF] + WF;
		t2 = (((B >>> 2) | (B << (32 - 2))) ^ ((B >>> 13)
			| (B << (32 - 13))) ^ ((B >>> 22) | (B << (32 - 22))))
			+ ((C & D) | ((C | D) & B));
		E += t1;
		A = t1 + t2;
		for (pcount = 16; pcount < 64; pcount += 16) {
			W0 += (((WE >>> 17) | (WE << (32 - 17))) ^ ((WE >>> 19)
				| (WE << (32 - 19))) ^ (WE >>> 10)) + W9
				+ (((W1 >>> 7) | (W1 << (32 - 7)))
				^ ((W1 >>> 18) | (W1 << (32 - 18)))
				^ (W1 >>> 3));
			t1 = H + (((E >>> 6) | (E << (32 - 6))) ^ ((E >>> 11)
				| (E << (32 - 11))) ^ ((E >>> 25)
				| (E << (32 - 25)))) + (((F ^ G) & E) ^ G)
				+ K[pcount + 0x0] + W0;
			t2 = (((A >>> 2) | (A << (32 - 2))) ^ ((A >>> 13)
				| (A << (32 - 13))) ^ ((A >>> 22)
				| (A << (32 - 22))))
				+ ((B & C) | ((B | C) & A));
			D += t1;
			H = t1 + t2;
			W1 += (((WF >>> 17) | (WF << (32 - 17))) ^ ((WF >>> 19)
				| (WF << (32 - 19))) ^ (WF >>> 10)) + WA
				+ (((W2 >>> 7) | (W2 << (32 - 7)))
				^ ((W2 >>> 18) | (W2 << (32 - 18)))
				^ (W2 >>> 3));
			t1 = G + (((D >>> 6) | (D << (32 - 6))) ^ ((D >>> 11)
				| (D << (32 - 11))) ^ ((D >>> 25)
				| (D << (32 - 25)))) + (((E ^ F) & D) ^ F)
				+ K[pcount + 0x1] + W1;
			t2 = (((H >>> 2) | (H << (32 - 2))) ^ ((H >>> 13)
				| (H << (32 - 13))) ^ ((H >>> 22)
				| (H << (32 - 22))))
				+ ((A & B) | ((A | B) & H));
			C += t1;
			G = t1 + t2;
			W2 += (((W0 >>> 17) | (W0 << (32 - 17))) ^ ((W0 >>> 19)
				| (W0 << (32 - 19))) ^ (W0 >>> 10)) + WB
				+ (((W3 >>> 7) | (W3 << (32 - 7)))
				^ ((W3 >>> 18) | (W3 << (32 - 18)))
				^ (W3 >>> 3));
			t1 = F + (((C >>> 6) | (C << (32 - 6))) ^ ((C >>> 11)
				| (C << (32 - 11))) ^ ((C >>> 25)
				| (C << (32 - 25)))) + (((D ^ E) & C) ^ E)
				+ K[pcount + 0x2] + W2;
			t2 = (((G >>> 2) | (G << (32 - 2))) ^ ((G >>> 13)
				| (G << (32 - 13))) ^ ((G >>> 22)
				| (G << (32 - 22))))
				+ ((H & A) | ((H | A) & G));
			B += t1;
			F = t1 + t2;
			W3 += (((W1 >>> 17) | (W1 << (32 - 17))) ^ ((W1 >>> 19)
				| (W1 << (32 - 19))) ^ (W1 >>> 10)) + WC
				+ (((W4 >>> 7) | (W4 << (32 - 7)))
				^ ((W4 >>> 18) | (W4 << (32 - 18)))
				^ (W4 >>> 3));
			t1 = E + (((B >>> 6) | (B << (32 - 6))) ^ ((B >>> 11)
				| (B << (32 - 11))) ^ ((B >>> 25)
				| (B << (32 - 25)))) + (((C ^ D) & B) ^ D)
				+ K[pcount + 0x3] + W3;
			t2 = (((F >>> 2) | (F << (32 - 2))) ^ ((F >>> 13)
				| (F << (32 - 13))) ^ ((F >>> 22)
				| (F << (32 - 22))))
				+ ((G & H) | ((G | H) & F));
			A += t1;
			E = t1 + t2;
			W4 += (((W2 >>> 17) | (W2 << (32 - 17))) ^ ((W2 >>> 19)
				| (W2 << (32 - 19))) ^ (W2 >>> 10)) + WD
				+ (((W5 >>> 7) | (W5 << (32 - 7)))
				^ ((W5 >>> 18) | (W5 << (32 - 18)))
				^ (W5 >>> 3));
			t1 = D + (((A >>> 6) | (A << (32 - 6))) ^ ((A >>> 11)
				| (A << (32 - 11))) ^ ((A >>> 25)
				| (A << (32 - 25)))) + (((B ^ C) & A) ^ C)
				+ K[pcount + 0x4] + W4;
			t2 = (((E >>> 2) | (E << (32 - 2))) ^ ((E >>> 13)
				| (E << (32 - 13))) ^ ((E >>> 22)
				| (E << (32 - 22))))
				+ ((F & G) | ((F | G) & E));
			H += t1;
			D = t1 + t2;
			W5 += (((W3 >>> 17) | (W3 << (32 - 17))) ^ ((W3 >>> 19)
				| (W3 << (32 - 19))) ^ (W3 >>> 10)) + WE
				+ (((W6 >>> 7) | (W6 << (32 - 7)))
				^ ((W6 >>> 18) | (W6 << (32 - 18)))
				^ (W6 >>> 3));
			t1 = C + (((H >>> 6) | (H << (32 - 6))) ^ ((H >>> 11)
				| (H << (32 - 11))) ^ ((H >>> 25)
				| (H << (32 - 25)))) + (((A ^ B) & H) ^ B)
				+ K[pcount + 0x5] + W5;
			t2 = (((D >>> 2) | (D << (32 - 2))) ^ ((D >>> 13)
				| (D << (32 - 13))) ^ ((D >>> 22)
				| (D << (32 - 22))))
				+ ((E & F) | ((E | F) & D));
			G += t1;
			C = t1 + t2;
			W6 += (((W4 >>> 17) | (W4 << (32 - 17))) ^ ((W4 >>> 19)
				| (W4 << (32 - 19))) ^ (W4 >>> 10)) + WF
				+ (((W7 >>> 7) | (W7 << (32 - 7)))
				^ ((W7 >>> 18) | (W7 << (32 - 18)))
				^ (W7 >>> 3));
			t1 = B + (((G >>> 6) | (G << (32 - 6))) ^ ((G >>> 11)
				| (G << (32 - 11))) ^ ((G >>> 25)
				| (G << (32 - 25)))) + (((H ^ A) & G) ^ A)
				+ K[pcount + 0x6] + W6;
			t2 = (((C >>> 2) | (C << (32 - 2))) ^ ((C >>> 13)
				| (C << (32 - 13))) ^ ((C >>> 22)
				| (C << (32 - 22))))
				+ ((D & E) | ((D | E) & C));
			F += t1;
			B = t1 + t2;
			W7 += (((W5 >>> 17) | (W5 << (32 - 17))) ^ ((W5 >>> 19)
				| (W5 << (32 - 19))) ^ (W5 >>> 10)) + W0
				+ (((W8 >>> 7) | (W8 << (32 - 7)))
				^ ((W8 >>> 18) | (W8 << (32 - 18)))
				^ (W8 >>> 3));
			t1 = A + (((F >>> 6) | (F << (32 - 6))) ^ ((F >>> 11)
				| (F << (32 - 11))) ^ ((F >>> 25)
				| (F << (32 - 25)))) + (((G ^ H) & F) ^ H)
				+ K[pcount + 0x7] + W7;
			t2 = (((B >>> 2) | (B << (32 - 2))) ^ ((B >>> 13)
				| (B << (32 - 13))) ^ ((B >>> 22)
				| (B << (32 - 22))))
				+ ((C & D) | ((C | D) & B));
			E += t1;
			A = t1 + t2;
			W8 += (((W6 >>> 17) | (W6 << (32 - 17))) ^ ((W6 >>> 19)
				| (W6 << (32 - 19))) ^ (W6 >>> 10)) + W1
				+ (((W9 >>> 7) | (W9 << (32 - 7)))
				^ ((W9 >>> 18) | (W9 << (32 - 18)))
				^ (W9 >>> 3));
			t1 = H + (((E >>> 6) | (E << (32 - 6))) ^ ((E >>> 11)
				| (E << (32 - 11))) ^ ((E >>> 25)
				| (E << (32 - 25)))) + (((F ^ G) & E) ^ G)
				+ K[pcount + 0x8] + W8;
			t2 = (((A >>> 2) | (A << (32 - 2))) ^ ((A >>> 13)
				| (A << (32 - 13))) ^ ((A >>> 22)
				| (A << (32 - 22))))
				+ ((B & C) | ((B | C) & A));
			D += t1;
			H = t1 + t2;
			W9 += (((W7 >>> 17) | (W7 << (32 - 17))) ^ ((W7 >>> 19)
				| (W7 << (32 - 19))) ^ (W7 >>> 10)) + W2
				+ (((WA >>> 7) | (WA << (32 - 7)))
				^ ((WA >>> 18) | (WA << (32 - 18)))
				^ (WA >>> 3));
			t1 = G + (((D >>> 6) | (D << (32 - 6))) ^ ((D >>> 11)
				| (D << (32 - 11))) ^ ((D >>> 25)
				| (D << (32 - 25)))) + (((E ^ F) & D) ^ F)
				+ K[pcount + 0x9] + W9;
			t2 = (((H >>> 2) | (H << (32 - 2))) ^ ((H >>> 13)
				| (H << (32 - 13))) ^ ((H >>> 22)
				| (H << (32 - 22))))
				+ ((A & B) | ((A | B) & H));
			C += t1;
			G = t1 + t2;
			WA += (((W8 >>> 17) | (W8 << (32 - 17))) ^ ((W8 >>> 19)
				| (W8 << (32 - 19))) ^ (W8 >>> 10)) + W3
				+ (((WB >>> 7) | (WB << (32 - 7)))
				^ ((WB >>> 18) | (WB << (32 - 18)))
				^ (WB >>> 3));
			t1 = F + (((C >>> 6) | (C << (32 - 6))) ^ ((C >>> 11)
				| (C << (32 - 11))) ^ ((C >>> 25)
				| (C << (32 - 25)))) + (((D ^ E) & C) ^ E)
				+ K[pcount + 0xA] + WA;
			t2 = (((G >>> 2) | (G << (32 - 2))) ^ ((G >>> 13)
				| (G << (32 - 13))) ^ ((G >>> 22)
				| (G << (32 - 22))))
				+ ((H & A) | ((H | A) & G));
			B += t1;
			F = t1 + t2;
			WB += (((W9 >>> 17) | (W9 << (32 - 17))) ^ ((W9 >>> 19)
				| (W9 << (32 - 19))) ^ (W9 >>> 10)) + W4
				+ (((WC >>> 7) | (WC << (32 - 7)))
				^ ((WC >>> 18) | (WC << (32 - 18)))
				^ (WC >>> 3));
			t1 = E + (((B >>> 6) | (B << (32 - 6))) ^ ((B >>> 11)
				| (B << (32 - 11))) ^ ((B >>> 25)
				| (B << (32 - 25)))) + (((C ^ D) & B) ^ D)
				+ K[pcount + 0xB] + WB;
			t2 = (((F >>> 2) | (F << (32 - 2))) ^ ((F >>> 13)
				| (F << (32 - 13))) ^ ((F >>> 22)
				| (F << (32 - 22))))
				+ ((G & H) | ((G | H) & F));
			A += t1;
			E = t1 + t2;
			WC += (((WA >>> 17) | (WA << (32 - 17))) ^ ((WA >>> 19)
				| (WA << (32 - 19))) ^ (WA >>> 10)) + W5
				+ (((WD >>> 7) | (WD << (32 - 7)))
				^ ((WD >>> 18) | (WD << (32 - 18)))
				^ (WD >>> 3));
			t1 = D + (((A >>> 6) | (A << (32 - 6))) ^ ((A >>> 11)
				| (A << (32 - 11))) ^ ((A >>> 25)
				| (A << (32 - 25)))) + (((B ^ C) & A) ^ C)
				+ K[pcount + 0xC] + WC;
			t2 = (((E >>> 2) | (E << (32 - 2))) ^ ((E >>> 13)
				| (E << (32 - 13))) ^ ((E >>> 22)
				| (E << (32 - 22))))
				+ ((F & G) | ((F | G) & E));
			H += t1;
			D = t1 + t2;
			WD += (((WB >>> 17) | (WB << (32 - 17))) ^ ((WB >>> 19)
				| (WB << (32 - 19))) ^ (WB >>> 10)) + W6
				+ (((WE >>> 7) | (WE << (32 - 7)))
				^ ((WE >>> 18) | (WE << (32 - 18)))
				^ (WE >>> 3));
			t1 = C + (((H >>> 6) | (H << (32 - 6))) ^ ((H >>> 11)
				| (H << (32 - 11))) ^ ((H >>> 25)
				| (H << (32 - 25)))) + (((A ^ B) & H) ^ B)
				+ K[pcount + 0xD] + WD;
			t2 = (((D >>> 2) | (D << (32 - 2))) ^ ((D >>> 13)
				| (D << (32 - 13))) ^ ((D >>> 22)
				| (D << (32 - 22))))
				+ ((E & F) | ((E | F) & D));
			G += t1;
			C = t1 + t2;
			WE += (((WC >>> 17) | (WC << (32 - 17))) ^ ((WC >>> 19)
				| (WC << (32 - 19))) ^ (WC >>> 10)) + W7
				+ (((WF >>> 7) | (WF << (32 - 7)))
				^ ((WF >>> 18) | (WF << (32 - 18)))
				^ (WF >>> 3));
			t1 = B + (((G >>> 6) | (G << (32 - 6))) ^ ((G >>> 11)
				| (G << (32 - 11))) ^ ((G >>> 25)
				| (G << (32 - 25)))) + (((H ^ A) & G) ^ A)
				+ K[pcount + 0xE] + WE;
			t2 = (((C >>> 2) | (C << (32 - 2))) ^ ((C >>> 13)
				| (C << (32 - 13))) ^ ((C >>> 22)
				| (C << (32 - 22))))
				+ ((D & E) | ((D | E) & C));
			F += t1;
			B = t1 + t2;
			WF += (((WD >>> 17) | (WD << (32 - 17))) ^ ((WD >>> 19)
				| (WD << (32 - 19))) ^ (WD >>> 10)) + W8
				+ (((W0 >>> 7) | (W0 << (32 - 7)))
				^ ((W0 >>> 18) | (W0 << (32 - 18)))
				^ (W0 >>> 3));
			t1 = A + (((F >>> 6) | (F << (32 - 6))) ^ ((F >>> 11)
				| (F << (32 - 11))) ^ ((F >>> 25)
				| (F << (32 - 25)))) + (((G ^ H) & F) ^ H)
				+ K[pcount + 0xF] + WF;
			t2 = (((B >>> 2) | (B << (32 - 2))) ^ ((B >>> 13)
				| (B << (32 - 13))) ^ ((B >>> 22)
				| (B << (32 - 22))))
				+ ((C & D) | ((C | D) & B));
			E += t1;
			A = t1 + t2;
		}

		currentVal[0] += A;
		currentVal[1] += B;
		currentVal[2] += C;
		currentVal[3] += D;
		currentVal[4] += E;
		currentVal[5] += F;
		currentVal[6] += G;
		currentVal[7] += H;
		*/
	}

	/** @see Digest */
	public String toString()
	{
		return "SHA-" + (getDigestLength() << 3);
	}
}
