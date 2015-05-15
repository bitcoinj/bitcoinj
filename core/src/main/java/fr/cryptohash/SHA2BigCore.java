// $Id: SHA2BigCore.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * This class implements SHA-384 and SHA-512, which differ only by the IV
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

abstract class SHA2BigCore extends MDHelper {

	/**
	 * Create the object.
	 */
	SHA2BigCore()
	{
		super(false, 16);
	}

	/** private special values. */
	private static final long[] K = {
		0x428A2F98D728AE22L, 0x7137449123EF65CDL, 0xB5C0FBCFEC4D3B2FL,
		0xE9B5DBA58189DBBCL, 0x3956C25BF348B538L, 0x59F111F1B605D019L,
		0x923F82A4AF194F9BL, 0xAB1C5ED5DA6D8118L, 0xD807AA98A3030242L,
		0x12835B0145706FBEL, 0x243185BE4EE4B28CL, 0x550C7DC3D5FFB4E2L,
		0x72BE5D74F27B896FL, 0x80DEB1FE3B1696B1L, 0x9BDC06A725C71235L,
		0xC19BF174CF692694L, 0xE49B69C19EF14AD2L, 0xEFBE4786384F25E3L,
		0x0FC19DC68B8CD5B5L, 0x240CA1CC77AC9C65L, 0x2DE92C6F592B0275L,
		0x4A7484AA6EA6E483L, 0x5CB0A9DCBD41FBD4L, 0x76F988DA831153B5L,
		0x983E5152EE66DFABL, 0xA831C66D2DB43210L, 0xB00327C898FB213FL,
		0xBF597FC7BEEF0EE4L, 0xC6E00BF33DA88FC2L, 0xD5A79147930AA725L,
		0x06CA6351E003826FL, 0x142929670A0E6E70L, 0x27B70A8546D22FFCL,
		0x2E1B21385C26C926L, 0x4D2C6DFC5AC42AEDL, 0x53380D139D95B3DFL,
		0x650A73548BAF63DEL, 0x766A0ABB3C77B2A8L, 0x81C2C92E47EDAEE6L,
		0x92722C851482353BL, 0xA2BFE8A14CF10364L, 0xA81A664BBC423001L,
		0xC24B8B70D0F89791L, 0xC76C51A30654BE30L, 0xD192E819D6EF5218L,
		0xD69906245565A910L, 0xF40E35855771202AL, 0x106AA07032BBD1B8L,
		0x19A4C116B8D2D0C8L, 0x1E376C085141AB53L, 0x2748774CDF8EEB99L,
		0x34B0BCB5E19B48A8L, 0x391C0CB3C5C95A63L, 0x4ED8AA4AE3418ACBL,
		0x5B9CCA4F7763E373L, 0x682E6FF3D6B2B8A3L, 0x748F82EE5DEFB2FCL,
		0x78A5636F43172F60L, 0x84C87814A1F0AB72L, 0x8CC702081A6439ECL,
		0x90BEFFFA23631E28L, 0xA4506CEBDE82BDE9L, 0xBEF9A3F7B2C67915L,
		0xC67178F2E372532BL, 0xCA273ECEEA26619CL, 0xD186B8C721C0C207L,
		0xEADA7DD6CDE0EB1EL, 0xF57D4F7FEE6ED178L, 0x06F067AA72176FBAL,
		0x0A637DC5A2C898A6L, 0x113F9804BEF90DAEL, 0x1B710B35131C471BL,
		0x28DB77F523047D84L, 0x32CAAB7B40C72493L, 0x3C9EBE0A15C9BEBCL,
		0x431D67C49C100D4CL, 0x4CC5D4BECB3E42B6L, 0x597F299CFC657E2AL,
		0x5FCB6FAB3AD6FAECL, 0x6C44198C4A475817L
	};

	private long[] currentVal, W;

	/** @see DigestEngine */
	protected Digest copyState(SHA2BigCore dst)
	{
		System.arraycopy(currentVal, 0, dst.currentVal, 0,
			currentVal.length);
		return super.copyState(dst);
	}

	/** @see Digest */
	public int getBlockLength()
	{
		return 128;
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		System.arraycopy(getInitVal(), 0, currentVal, 0, 8);
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
		makeMDPadding();
		int olen = getDigestLength();
		for (int i = 0, j = 0; j < olen; i ++, j += 8)
			encodeBELong(currentVal[i], output, outputOffset + j);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		currentVal = new long[8];
		W = new long[80];
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
	 * Perform a circular rotation by {@code n} to the left
	 * of the 64-bit word {@code x}. The {@code n} parameter
	 * must lie between 1 and 63 (inclusive).
	 *
	 * @param x   the value to rotate
	 * @param n   the rotation count (between 1 and 63)
	 * @return  the rotated value
	*/
	static private long circularLeft(long x, int n)
	{
		return (x << n) | (x >>> (64 - n));
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		long A = currentVal[0];
		long B = currentVal[1];
		long C = currentVal[2];
		long D = currentVal[3];
		long E = currentVal[4];
		long F = currentVal[5];
		long G = currentVal[6];
		long H = currentVal[7];

		for (int i = 0; i < 16; i ++)
			W[i] = decodeBELong(data, 8 * i);
		for (int i = 16; i < 80; i ++) {
			W[i] = (circularLeft(W[i - 2], 45)
				^ circularLeft(W[i - 2], 3)
				^ (W[i - 2] >>> 6))
				+ W[i - 7]
				+ (circularLeft(W[i - 15], 63)
				^ circularLeft(W[i - 15], 56)
				^ (W[i - 15] >>> 7))
				+ W[i - 16];
		}
		for (int i = 0; i < 80; i ++) {
			/*
			 * Microsoft JVM (old JVM with IE 5.5) has trouble
			 * with complex expressions involving the "long"
			 * type. Hence, we split these expressions into
			 * simpler elementary expressions. Such a split
			 * should not harm recent JDK optimizers.
			 */

			long T1 = circularLeft(E, 50);
			T1 ^= circularLeft(E, 46);
			T1 ^= circularLeft(E, 23);
			T1 += H;
			T1 += (F & E) ^ (G & ~E);
			T1 += K[i];
			T1 += W[i];

			long T2 = circularLeft(A, 36);
			T2 ^= circularLeft(A, 30);
			T2 ^= circularLeft(A, 25);
			T2 += (A & B) ^ (A & C) ^ (B & C);

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
	}

	/** @see Digest */
	public String toString()
	{
		return "SHA-" + (getDigestLength() << 3);
	}
}
