// $Id: HAVALCore.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * This class implements the HAVAL digest algorithm, which accepts 15
 * variants based on the number of passes and digest output.
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

abstract class HAVALCore extends DigestEngine {

	/**
	 * Create the object.
	 *
	 * @param outputLength   output length (in bits)
	 * @param passes         number of passes (3, 4 or 5)
	 */
	HAVALCore(int outputLength, int passes)
	{
		olen = outputLength >> 5;
		this.passes = passes;
	}

	/**
	 * Output length, in 32-bit words (4, 5, 6, 7, or 8).
	 */
	private int olen;

	/**
	 * Number of passes (3, 4 or 5).
	 */
	private int passes;

	/**
	 * Padding buffer.
	 */
	private byte[] padBuf;

	/**
	 * State variables.
	 */
	private int s0, s1, s2, s3, s4, s5, s6, s7;

	/**
	 * Pre-allocated array for input words.
	 */
	private int[] inw;

	/** @see DigestEngine */
	protected Digest copyState(HAVALCore dst)
	{
		dst.olen = olen;
		dst.passes = passes;
		dst.s0 = s0;
		dst.s1 = s1;
		dst.s2 = s2;
		dst.s3 = s3;
		dst.s4 = s4;
		dst.s5 = s5;
		dst.s6 = s6;
		dst.s7 = s7;
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
		s0 = 0x243F6A88;
		s1 = 0x85A308D3;
		s2 = 0x13198A2E;
		s3 = 0x03707344;
		s4 = 0xA4093822;
		s5 = 0x299F31D0;
		s6 = 0x082EFA98;
		s7 = 0xEC4E6C89;
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		int dataLen = flush();
		long currentLength =
			((getBlockCount() << 7) + (long)dataLen) << 3;
		padBuf[0] = (byte)(0x01 | (passes << 3));
		padBuf[1] = (byte)(olen << 3);
		encodeLEInt((int)currentLength, padBuf, 2);
		encodeLEInt((int)(currentLength >>> 32), padBuf, 6);
		int endLen = (dataLen + 138) & ~127;
		update((byte)0x01);
		for (int i = dataLen + 1; i < (endLen - 10); i ++)
			update((byte)0);
		update(padBuf);

		/*
		 * This code is used only for debugging purposes.
		 *
		if (flush() != 0)
			throw new Error("panic: buffering went astray");
		 *
		 */

		writeOutput(output, outputOffset);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		padBuf = new byte[10];
		inw = new int[32];
		engineReset();
	}

	private static final int[] K2 = {
		0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
		0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
		0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC,
		0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96,
		0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7,
		0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69,
		0xA458FEA3, 0xF4933D7E, 0x0D95748F, 0x728EB658,
		0x718BCD58, 0x82154AEE, 0x7B54A41D, 0xC25A59B5
	};

	private static final int[] K3 = {
		0x9C30D539, 0x2AF26013, 0xC5D1B023, 0x286085F0,
		0xCA417918, 0xB8DB38EF, 0x8E79DCB0, 0x603A180E,
		0x6C9E0E8B, 0xB01E8A3E, 0xD71577C1, 0xBD314B27,
		0x78AF2FDA, 0x55605C60, 0xE65525F3, 0xAA55AB94,
		0x57489862, 0x63E81440, 0x55CA396A, 0x2AAB10B6,
		0xB4CC5C34, 0x1141E8CE, 0xA15486AF, 0x7C72E993,
		0xB3EE1411, 0x636FBC2A, 0x2BA9C55D, 0x741831F6,
		0xCE5C3E16, 0x9B87931E, 0xAFD6BA33, 0x6C24CF5C
	};

	private static final int[] K4 = {
		0x7A325381, 0x28958677, 0x3B8F4898, 0x6B4BB9AF,
		0xC4BFE81B, 0x66282193, 0x61D809CC, 0xFB21A991,
		0x487CAC60, 0x5DEC8032, 0xEF845D5D, 0xE98575B1,
		0xDC262302, 0xEB651B88, 0x23893E81, 0xD396ACC5,
		0x0F6D6FF3, 0x83F44239, 0x2E0B4482, 0xA4842004,
		0x69C8F04A, 0x9E1F9B5E, 0x21C66842, 0xF6E96C9A,
		0x670C9C61, 0xABD388F0, 0x6A51A0D2, 0xD8542F68,
		0x960FA728, 0xAB5133A3, 0x6EEF0B6C, 0x137A3BE4
	};

	private static final int[] K5 = {
		0xBA3BF050, 0x7EFB2A98, 0xA1F1651D, 0x39AF0176,
		0x66CA593E, 0x82430E88, 0x8CEE8619, 0x456F9FB4,
		0x7D84A5C3, 0x3B8B5EBE, 0xE06F75D8, 0x85C12073,
		0x401A449F, 0x56C16AA6, 0x4ED3AA62, 0x363F7706,
		0x1BFEDF72, 0x429B023D, 0x37D0D724, 0xD00A1248,
		0xDB0FEAD3, 0x49F1C09B, 0x075372C9, 0x80991B7B,
		0x25D479D8, 0xF6E8DEF7, 0xE3FE501A, 0xB6794C3B,
		0x976CE0BD, 0x04C006BA, 0xC1A94FB6, 0x409F60C4
	};

	private static final int[] wp2 = {
		 5, 14, 26, 18, 11, 28,  7, 16,  0, 23, 20, 22,  1, 10,  4,  8,
		30,  3, 21,  9, 17, 24, 29,  6, 19, 12, 15, 13,  2, 25, 31, 27
	};

	private static final int[] wp3 = {
		19,  9,  4, 20, 28, 17,  8, 22, 29, 14, 25, 12, 24, 30, 16, 26,
		31, 15,  7,  3,  1,  0, 18, 27, 13,  6, 21, 10, 23, 11,  5,  2
	};

	private static final int[] wp4 = {
		24,  4,  0, 14,  2,  7, 28, 23, 26,  6, 30, 20, 18, 25, 19,  3,
		22, 11, 31, 21,  8, 27, 12,  9,  1, 29,  5, 15, 17, 10, 16, 13
	};

	private static final int[] wp5 = {
		27,  3, 21, 26, 17, 11, 20, 29, 19,  0, 12,  7, 13,  8, 31, 10,
		 5,  9, 14, 30, 18,  6, 28, 24,  2, 23, 16, 22,  4,  1, 25, 15
	};

	/**
	 * Encode the 32-bit word {@code val} into the array
	 * {@code buf} at offset {@code buf}, in little-endian
	 * convention (least significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	private static final void encodeLEInt(int val, byte[] buf, int off)
	{
		buf[off + 3] = (byte)((val >> 24) & 0xff);
		buf[off + 2] = (byte)((val >> 16) & 0xff);
		buf[off + 1] = (byte)((val >> 8) & 0xff);
		buf[off + 0] = (byte)(val & 0xff);
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
		return (buf[off] & 0xFF)
			| ((buf[off + 1] & 0xFF) << 8)
			| ((buf[off + 2] & 0xFF) << 16)
			| ((buf[off + 3] & 0xFF) << 24);
	}

	/**
	 * Circular rotation of a 32-bit word to the left. The rotation
	 * count must lie between 1 and 31 (inclusive).
	 *
	 * @param x   the value to rotate
	 * @param n   the rotation count
	 * @return  the rotated value
	 */
	private static final int circularLeft(int x, int n)
	{
		return (x << n) | (x >>> (32 - n));
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		for (int i = 0; i < 32; i ++)
			inw[i] = decodeLEInt(data, 4 * i);

		int save0 = s0;
		int save1 = s1;
		int save2 = s2;
		int save3 = s3;
		int save4 = s4;
		int save5 = s5;
		int save6 = s6;
		int save7 = s7;
		switch (passes) {
		case 3:
			pass31(inw);
			pass32(inw);
			pass33(inw);
			break;
		case 4:
			pass41(inw);
			pass42(inw);
			pass43(inw);
			pass44(inw);
			break;
		case 5:
			pass51(inw);
			pass52(inw);
			pass53(inw);
			pass54(inw);
			pass55(inw);
			break;
		}
		s0 += save0;
		s1 += save1;
		s2 += save2;
		s3 += save3;
		s4 += save4;
		s5 += save5;
		s6 += save6;
		s7 += save7;
	}

	private static final int F1(int x6, int x5, int x4,
		int x3, int x2, int x1, int x0)
	{
		return (x1 & x4) ^ (x2 & x5) ^ (x3 & x6) ^ (x0 & x1) ^ x0;
	}

	private static final int F2(int x6, int x5, int x4,
		int x3, int x2, int x1, int x0)
	{
		return (x2 & ((x1 & ~x3) ^ (x4 & x5) ^ x6 ^ x0))
			^ (x4 & (x1 ^ x5)) ^ ((x3 & x5) ^ x0);
	}

	private static final int F3(int x6, int x5, int x4,
		int x3, int x2, int x1, int x0)
	{
		return (x3 & ((x1 & x2) ^ x6 ^ x0))
			^ (x1 & x4) ^ (x2 & x5) ^ x0;
	}

	private static final int F4(int x6, int x5, int x4,
		int x3, int x2, int x1, int x0)
	{
		return (x3 & ((x1 & x2) ^ (x4 | x6) ^ x5))
			^ (x4 & ((~x2 & x5) ^ x1 ^ x6 ^ x0)) ^ (x2 & x6) ^ x0;
	}

	private static final int F5(int x6, int x5, int x4,
		int x3, int x2, int x1, int x0)
	{
		return (x0 & ~((x1 & x2 & x3) ^ x5))
			^ (x1 & x4) ^ (x2 & x5) ^ (x3 & x6);
	}

	private final void pass31(int[] inw)
	{
		int x0 = s0, x1 = s1, x2 = s2, x3 = s3;
		int x4 = s4, x5 = s5, x6 = s6, x7 = s7;
		for (int i = 0; i < 32; i += 8) {
			x7 = circularLeft(F1(x1, x0, x3, x5, x6, x2, x4), 25)
				+ circularLeft(x7, 21) + inw[i + 0];
			x6 = circularLeft(F1(x0, x7, x2, x4, x5, x1, x3), 25)
				+ circularLeft(x6, 21) + inw[i + 1];
			x5 = circularLeft(F1(x7, x6, x1, x3, x4, x0, x2), 25)
				+ circularLeft(x5, 21) + inw[i + 2];
			x4 = circularLeft(F1(x6, x5, x0, x2, x3, x7, x1), 25)
				+ circularLeft(x4, 21) + inw[i + 3];
			x3 = circularLeft(F1(x5, x4, x7, x1, x2, x6, x0), 25)
				+ circularLeft(x3, 21) + inw[i + 4];
			x2 = circularLeft(F1(x4, x3, x6, x0, x1, x5, x7), 25)
				+ circularLeft(x2, 21) + inw[i + 5];
			x1 = circularLeft(F1(x3, x2, x5, x7, x0, x4, x6), 25)
				+ circularLeft(x1, 21) + inw[i + 6];
			x0 = circularLeft(F1(x2, x1, x4, x6, x7, x3, x5), 25)
				+ circularLeft(x0, 21) + inw[i + 7];
		}
		s0 = x0; s1 = x1; s2 = x2; s3 = x3;
		s4 = x4; s5 = x5; s6 = x6; s7 = x7;
	}

	private final void pass32(int[] inw)
	{
		int x0 = s0, x1 = s1, x2 = s2, x3 = s3;
		int x4 = s4, x5 = s5, x6 = s6, x7 = s7;
		for (int i = 0; i < 32; i += 8) {
			x7 = circularLeft(F2(x4, x2, x1, x0, x5, x3, x6), 25)
				+ circularLeft(x7, 21)
				+ inw[wp2[i + 0]] + K2[i + 0];
			x6 = circularLeft(F2(x3, x1, x0, x7, x4, x2, x5), 25)
				+ circularLeft(x6, 21)
				+ inw[wp2[i + 1]] + K2[i + 1];
			x5 = circularLeft(F2(x2, x0, x7, x6, x3, x1, x4), 25)
				+ circularLeft(x5, 21)
				+ inw[wp2[i + 2]] + K2[i + 2];
			x4 = circularLeft(F2(x1, x7, x6, x5, x2, x0, x3), 25)
				+ circularLeft(x4, 21)
				+ inw[wp2[i + 3]] + K2[i + 3];
			x3 = circularLeft(F2(x0, x6, x5, x4, x1, x7, x2), 25)
				+ circularLeft(x3, 21)
				+ inw[wp2[i + 4]] + K2[i + 4];
			x2 = circularLeft(F2(x7, x5, x4, x3, x0, x6, x1), 25)
				+ circularLeft(x2, 21)
				+ inw[wp2[i + 5]] + K2[i + 5];
			x1 = circularLeft(F2(x6, x4, x3, x2, x7, x5, x0), 25)
				+ circularLeft(x1, 21)
				+ inw[wp2[i + 6]] + K2[i + 6];
			x0 = circularLeft(F2(x5, x3, x2, x1, x6, x4, x7), 25)
				+ circularLeft(x0, 21)
				+ inw[wp2[i + 7]] + K2[i + 7];
		}
		s0 = x0; s1 = x1; s2 = x2; s3 = x3;
		s4 = x4; s5 = x5; s6 = x6; s7 = x7;
	}

	private final void pass33(int[] inw)
	{
		int x0 = s0, x1 = s1, x2 = s2, x3 = s3;
		int x4 = s4, x5 = s5, x6 = s6, x7 = s7;
		for (int i = 0; i < 32; i += 8) {
			x7 = circularLeft(F3(x6, x1, x2, x3, x4, x5, x0), 25)
				+ circularLeft(x7, 21)
				+ inw[wp3[i + 0]] + K3[i + 0];
			x6 = circularLeft(F3(x5, x0, x1, x2, x3, x4, x7), 25)
				+ circularLeft(x6, 21)
				+ inw[wp3[i + 1]] + K3[i + 1];
			x5 = circularLeft(F3(x4, x7, x0, x1, x2, x3, x6), 25)
				+ circularLeft(x5, 21)
				+ inw[wp3[i + 2]] + K3[i + 2];
			x4 = circularLeft(F3(x3, x6, x7, x0, x1, x2, x5), 25)
				+ circularLeft(x4, 21)
				+ inw[wp3[i + 3]] + K3[i + 3];
			x3 = circularLeft(F3(x2, x5, x6, x7, x0, x1, x4), 25)
				+ circularLeft(x3, 21)
				+ inw[wp3[i + 4]] + K3[i + 4];
			x2 = circularLeft(F3(x1, x4, x5, x6, x7, x0, x3), 25)
				+ circularLeft(x2, 21)
				+ inw[wp3[i + 5]] + K3[i + 5];
			x1 = circularLeft(F3(x0, x3, x4, x5, x6, x7, x2), 25)
				+ circularLeft(x1, 21)
				+ inw[wp3[i + 6]] + K3[i + 6];
			x0 = circularLeft(F3(x7, x2, x3, x4, x5, x6, x1), 25)
				+ circularLeft(x0, 21)
				+ inw[wp3[i + 7]] + K3[i + 7];
		}
		s0 = x0; s1 = x1; s2 = x2; s3 = x3;
		s4 = x4; s5 = x5; s6 = x6; s7 = x7;
	}

	private final void pass41(int[] inw)
	{
		int x0 = s0, x1 = s1, x2 = s2, x3 = s3;
		int x4 = s4, x5 = s5, x6 = s6, x7 = s7;
		for (int i = 0; i < 32; i += 8) {
			x7 = circularLeft(F1(x2, x6, x1, x4, x5, x3, x0), 25)
				+ circularLeft(x7, 21) + inw[i + 0];
			x6 = circularLeft(F1(x1, x5, x0, x3, x4, x2, x7), 25)
				+ circularLeft(x6, 21) + inw[i + 1];
			x5 = circularLeft(F1(x0, x4, x7, x2, x3, x1, x6), 25)
				+ circularLeft(x5, 21) + inw[i + 2];
			x4 = circularLeft(F1(x7, x3, x6, x1, x2, x0, x5), 25)
				+ circularLeft(x4, 21) + inw[i + 3];
			x3 = circularLeft(F1(x6, x2, x5, x0, x1, x7, x4), 25)
				+ circularLeft(x3, 21) + inw[i + 4];
			x2 = circularLeft(F1(x5, x1, x4, x7, x0, x6, x3), 25)
				+ circularLeft(x2, 21) + inw[i + 5];
			x1 = circularLeft(F1(x4, x0, x3, x6, x7, x5, x2), 25)
				+ circularLeft(x1, 21) + inw[i + 6];
			x0 = circularLeft(F1(x3, x7, x2, x5, x6, x4, x1), 25)
				+ circularLeft(x0, 21) + inw[i + 7];
		}
		s0 = x0; s1 = x1; s2 = x2; s3 = x3;
		s4 = x4; s5 = x5; s6 = x6; s7 = x7;
	}

	private final void pass42(int[] inw)
	{
		int x0 = s0, x1 = s1, x2 = s2, x3 = s3;
		int x4 = s4, x5 = s5, x6 = s6, x7 = s7;
		for (int i = 0; i < 32; i += 8) {
			x7 = circularLeft(F2(x3, x5, x2, x0, x1, x6, x4), 25)
				+ circularLeft(x7, 21)
				+ inw[wp2[i + 0]] + K2[i + 0];
			x6 = circularLeft(F2(x2, x4, x1, x7, x0, x5, x3), 25)
				+ circularLeft(x6, 21)
				+ inw[wp2[i + 1]] + K2[i + 1];
			x5 = circularLeft(F2(x1, x3, x0, x6, x7, x4, x2), 25)
				+ circularLeft(x5, 21)
				+ inw[wp2[i + 2]] + K2[i + 2];
			x4 = circularLeft(F2(x0, x2, x7, x5, x6, x3, x1), 25)
				+ circularLeft(x4, 21)
				+ inw[wp2[i + 3]] + K2[i + 3];
			x3 = circularLeft(F2(x7, x1, x6, x4, x5, x2, x0), 25)
				+ circularLeft(x3, 21)
				+ inw[wp2[i + 4]] + K2[i + 4];
			x2 = circularLeft(F2(x6, x0, x5, x3, x4, x1, x7), 25)
				+ circularLeft(x2, 21)
				+ inw[wp2[i + 5]] + K2[i + 5];
			x1 = circularLeft(F2(x5, x7, x4, x2, x3, x0, x6), 25)
				+ circularLeft(x1, 21)
				+ inw[wp2[i + 6]] + K2[i + 6];
			x0 = circularLeft(F2(x4, x6, x3, x1, x2, x7, x5), 25)
				+ circularLeft(x0, 21)
				+ inw[wp2[i + 7]] + K2[i + 7];
		}
		s0 = x0; s1 = x1; s2 = x2; s3 = x3;
		s4 = x4; s5 = x5; s6 = x6; s7 = x7;
	}

	private final void pass43(int[] inw)
	{
		int x0 = s0, x1 = s1, x2 = s2, x3 = s3;
		int x4 = s4, x5 = s5, x6 = s6, x7 = s7;
		for (int i = 0; i < 32; i += 8) {
			x7 = circularLeft(F3(x1, x4, x3, x6, x0, x2, x5), 25)
				+ circularLeft(x7, 21)
				+ inw[wp3[i + 0]] + K3[i + 0];
			x6 = circularLeft(F3(x0, x3, x2, x5, x7, x1, x4), 25)
				+ circularLeft(x6, 21)
				+ inw[wp3[i + 1]] + K3[i + 1];
			x5 = circularLeft(F3(x7, x2, x1, x4, x6, x0, x3), 25)
				+ circularLeft(x5, 21)
				+ inw[wp3[i + 2]] + K3[i + 2];
			x4 = circularLeft(F3(x6, x1, x0, x3, x5, x7, x2), 25)
				+ circularLeft(x4, 21)
				+ inw[wp3[i + 3]] + K3[i + 3];
			x3 = circularLeft(F3(x5, x0, x7, x2, x4, x6, x1), 25)
				+ circularLeft(x3, 21)
				+ inw[wp3[i + 4]] + K3[i + 4];
			x2 = circularLeft(F3(x4, x7, x6, x1, x3, x5, x0), 25)
				+ circularLeft(x2, 21)
				+ inw[wp3[i + 5]] + K3[i + 5];
			x1 = circularLeft(F3(x3, x6, x5, x0, x2, x4, x7), 25)
				+ circularLeft(x1, 21)
				+ inw[wp3[i + 6]] + K3[i + 6];
			x0 = circularLeft(F3(x2, x5, x4, x7, x1, x3, x6), 25)
				+ circularLeft(x0, 21)
				+ inw[wp3[i + 7]] + K3[i + 7];
		}
		s0 = x0; s1 = x1; s2 = x2; s3 = x3;
		s4 = x4; s5 = x5; s6 = x6; s7 = x7;
	}

	private final void pass44(int[] inw)
	{
		int x0 = s0, x1 = s1, x2 = s2, x3 = s3;
		int x4 = s4, x5 = s5, x6 = s6, x7 = s7;
		for (int i = 0; i < 32; i += 8) {
			x7 = circularLeft(F4(x6, x4, x0, x5, x2, x1, x3), 25)
				+ circularLeft(x7, 21)
				+ inw[wp4[i + 0]] + K4[i + 0];
			x6 = circularLeft(F4(x5, x3, x7, x4, x1, x0, x2), 25)
				+ circularLeft(x6, 21)
				+ inw[wp4[i + 1]] + K4[i + 1];
			x5 = circularLeft(F4(x4, x2, x6, x3, x0, x7, x1), 25)
				+ circularLeft(x5, 21)
				+ inw[wp4[i + 2]] + K4[i + 2];
			x4 = circularLeft(F4(x3, x1, x5, x2, x7, x6, x0), 25)
				+ circularLeft(x4, 21)
				+ inw[wp4[i + 3]] + K4[i + 3];
			x3 = circularLeft(F4(x2, x0, x4, x1, x6, x5, x7), 25)
				+ circularLeft(x3, 21)
				+ inw[wp4[i + 4]] + K4[i + 4];
			x2 = circularLeft(F4(x1, x7, x3, x0, x5, x4, x6), 25)
				+ circularLeft(x2, 21)
				+ inw[wp4[i + 5]] + K4[i + 5];
			x1 = circularLeft(F4(x0, x6, x2, x7, x4, x3, x5), 25)
				+ circularLeft(x1, 21)
				+ inw[wp4[i + 6]] + K4[i + 6];
			x0 = circularLeft(F4(x7, x5, x1, x6, x3, x2, x4), 25)
				+ circularLeft(x0, 21)
				+ inw[wp4[i + 7]] + K4[i + 7];
		}
		s0 = x0; s1 = x1; s2 = x2; s3 = x3;
		s4 = x4; s5 = x5; s6 = x6; s7 = x7;
	}

	private final void pass51(int[] inw)
	{
		int x0 = s0, x1 = s1, x2 = s2, x3 = s3;
		int x4 = s4, x5 = s5, x6 = s6, x7 = s7;
		for (int i = 0; i < 32; i += 8) {
			x7 = circularLeft(F1(x3, x4, x1, x0, x5, x2, x6), 25)
				+ circularLeft(x7, 21) + inw[i + 0];
			x6 = circularLeft(F1(x2, x3, x0, x7, x4, x1, x5), 25)
				+ circularLeft(x6, 21) + inw[i + 1];
			x5 = circularLeft(F1(x1, x2, x7, x6, x3, x0, x4), 25)
				+ circularLeft(x5, 21) + inw[i + 2];
			x4 = circularLeft(F1(x0, x1, x6, x5, x2, x7, x3), 25)
				+ circularLeft(x4, 21) + inw[i + 3];
			x3 = circularLeft(F1(x7, x0, x5, x4, x1, x6, x2), 25)
				+ circularLeft(x3, 21) + inw[i + 4];
			x2 = circularLeft(F1(x6, x7, x4, x3, x0, x5, x1), 25)
				+ circularLeft(x2, 21) + inw[i + 5];
			x1 = circularLeft(F1(x5, x6, x3, x2, x7, x4, x0), 25)
				+ circularLeft(x1, 21) + inw[i + 6];
			x0 = circularLeft(F1(x4, x5, x2, x1, x6, x3, x7), 25)
				+ circularLeft(x0, 21) + inw[i + 7];
		}
		s0 = x0; s1 = x1; s2 = x2; s3 = x3;
		s4 = x4; s5 = x5; s6 = x6; s7 = x7;
	}

	private final void pass52(int[] inw)
	{
		int x0 = s0, x1 = s1, x2 = s2, x3 = s3;
		int x4 = s4, x5 = s5, x6 = s6, x7 = s7;
		for (int i = 0; i < 32; i += 8) {
			x7 = circularLeft(F2(x6, x2, x1, x0, x3, x4, x5), 25)
				+ circularLeft(x7, 21)
				+ inw[wp2[i + 0]] + K2[i + 0];
			x6 = circularLeft(F2(x5, x1, x0, x7, x2, x3, x4), 25)
				+ circularLeft(x6, 21)
				+ inw[wp2[i + 1]] + K2[i + 1];
			x5 = circularLeft(F2(x4, x0, x7, x6, x1, x2, x3), 25)
				+ circularLeft(x5, 21)
				+ inw[wp2[i + 2]] + K2[i + 2];
			x4 = circularLeft(F2(x3, x7, x6, x5, x0, x1, x2), 25)
				+ circularLeft(x4, 21)
				+ inw[wp2[i + 3]] + K2[i + 3];
			x3 = circularLeft(F2(x2, x6, x5, x4, x7, x0, x1), 25)
				+ circularLeft(x3, 21)
				+ inw[wp2[i + 4]] + K2[i + 4];
			x2 = circularLeft(F2(x1, x5, x4, x3, x6, x7, x0), 25)
				+ circularLeft(x2, 21)
				+ inw[wp2[i + 5]] + K2[i + 5];
			x1 = circularLeft(F2(x0, x4, x3, x2, x5, x6, x7), 25)
				+ circularLeft(x1, 21)
				+ inw[wp2[i + 6]] + K2[i + 6];
			x0 = circularLeft(F2(x7, x3, x2, x1, x4, x5, x6), 25)
				+ circularLeft(x0, 21)
				+ inw[wp2[i + 7]] + K2[i + 7];
		}
		s0 = x0; s1 = x1; s2 = x2; s3 = x3;
		s4 = x4; s5 = x5; s6 = x6; s7 = x7;
	}

	private final void pass53(int[] inw)
	{
		int x0 = s0, x1 = s1, x2 = s2, x3 = s3;
		int x4 = s4, x5 = s5, x6 = s6, x7 = s7;
		for (int i = 0; i < 32; i += 8) {
			x7 = circularLeft(F3(x2, x6, x0, x4, x3, x1, x5), 25)
				+ circularLeft(x7, 21)
				+ inw[wp3[i + 0]] + K3[i + 0];
			x6 = circularLeft(F3(x1, x5, x7, x3, x2, x0, x4), 25)
				+ circularLeft(x6, 21)
				+ inw[wp3[i + 1]] + K3[i + 1];
			x5 = circularLeft(F3(x0, x4, x6, x2, x1, x7, x3), 25)
				+ circularLeft(x5, 21)
				+ inw[wp3[i + 2]] + K3[i + 2];
			x4 = circularLeft(F3(x7, x3, x5, x1, x0, x6, x2), 25)
				+ circularLeft(x4, 21)
				+ inw[wp3[i + 3]] + K3[i + 3];
			x3 = circularLeft(F3(x6, x2, x4, x0, x7, x5, x1), 25)
				+ circularLeft(x3, 21)
				+ inw[wp3[i + 4]] + K3[i + 4];
			x2 = circularLeft(F3(x5, x1, x3, x7, x6, x4, x0), 25)
				+ circularLeft(x2, 21)
				+ inw[wp3[i + 5]] + K3[i + 5];
			x1 = circularLeft(F3(x4, x0, x2, x6, x5, x3, x7), 25)
				+ circularLeft(x1, 21)
				+ inw[wp3[i + 6]] + K3[i + 6];
			x0 = circularLeft(F3(x3, x7, x1, x5, x4, x2, x6), 25)
				+ circularLeft(x0, 21)
				+ inw[wp3[i + 7]] + K3[i + 7];
		}
		s0 = x0; s1 = x1; s2 = x2; s3 = x3;
		s4 = x4; s5 = x5; s6 = x6; s7 = x7;
	}

	private final void pass54(int[] inw)
	{
		int x0 = s0, x1 = s1, x2 = s2, x3 = s3;
		int x4 = s4, x5 = s5, x6 = s6, x7 = s7;
		for (int i = 0; i < 32; i += 8) {
			x7 = circularLeft(F4(x1, x5, x3, x2, x0, x4, x6), 25)
				+ circularLeft(x7, 21)
				+ inw[wp4[i + 0]] + K4[i + 0];
			x6 = circularLeft(F4(x0, x4, x2, x1, x7, x3, x5), 25)
				+ circularLeft(x6, 21)
				+ inw[wp4[i + 1]] + K4[i + 1];
			x5 = circularLeft(F4(x7, x3, x1, x0, x6, x2, x4), 25)
				+ circularLeft(x5, 21)
				+ inw[wp4[i + 2]] + K4[i + 2];
			x4 = circularLeft(F4(x6, x2, x0, x7, x5, x1, x3), 25)
				+ circularLeft(x4, 21)
				+ inw[wp4[i + 3]] + K4[i + 3];
			x3 = circularLeft(F4(x5, x1, x7, x6, x4, x0, x2), 25)
				+ circularLeft(x3, 21)
				+ inw[wp4[i + 4]] + K4[i + 4];
			x2 = circularLeft(F4(x4, x0, x6, x5, x3, x7, x1), 25)
				+ circularLeft(x2, 21)
				+ inw[wp4[i + 5]] + K4[i + 5];
			x1 = circularLeft(F4(x3, x7, x5, x4, x2, x6, x0), 25)
				+ circularLeft(x1, 21)
				+ inw[wp4[i + 6]] + K4[i + 6];
			x0 = circularLeft(F4(x2, x6, x4, x3, x1, x5, x7), 25)
				+ circularLeft(x0, 21)
				+ inw[wp4[i + 7]] + K4[i + 7];
		}
		s0 = x0; s1 = x1; s2 = x2; s3 = x3;
		s4 = x4; s5 = x5; s6 = x6; s7 = x7;
	}

	private final void pass55(int[] inw)
	{
		int x0 = s0, x1 = s1, x2 = s2, x3 = s3;
		int x4 = s4, x5 = s5, x6 = s6, x7 = s7;
		for (int i = 0; i < 32; i += 8) {
			x7 = circularLeft(F5(x2, x5, x0, x6, x4, x3, x1), 25)
				+ circularLeft(x7, 21)
				+ inw[wp5[i + 0]] + K5[i + 0];
			x6 = circularLeft(F5(x1, x4, x7, x5, x3, x2, x0), 25)
				+ circularLeft(x6, 21)
				+ inw[wp5[i + 1]] + K5[i + 1];
			x5 = circularLeft(F5(x0, x3, x6, x4, x2, x1, x7), 25)
				+ circularLeft(x5, 21)
				+ inw[wp5[i + 2]] + K5[i + 2];
			x4 = circularLeft(F5(x7, x2, x5, x3, x1, x0, x6), 25)
				+ circularLeft(x4, 21)
				+ inw[wp5[i + 3]] + K5[i + 3];
			x3 = circularLeft(F5(x6, x1, x4, x2, x0, x7, x5), 25)
				+ circularLeft(x3, 21)
				+ inw[wp5[i + 4]] + K5[i + 4];
			x2 = circularLeft(F5(x5, x0, x3, x1, x7, x6, x4), 25)
				+ circularLeft(x2, 21)
				+ inw[wp5[i + 5]] + K5[i + 5];
			x1 = circularLeft(F5(x4, x7, x2, x0, x6, x5, x3), 25)
				+ circularLeft(x1, 21)
				+ inw[wp5[i + 6]] + K5[i + 6];
			x0 = circularLeft(F5(x3, x6, x1, x7, x5, x4, x2), 25)
				+ circularLeft(x0, 21)
				+ inw[wp5[i + 7]] + K5[i + 7];
		}
		s0 = x0; s1 = x1; s2 = x2; s3 = x3;
		s4 = x4; s5 = x5; s6 = x6; s7 = x7;
	}

	private static final int mix128(int a0, int a1, int a2, int a3, int n)
	{
		int tmp = (a0 & 0x000000FF)
			| (a1 & 0x0000FF00)
			| (a2 & 0x00FF0000)
			| (a3 & 0xFF000000);
		if (n > 0)
			tmp = circularLeft(tmp, n);
		return tmp;
	}

	private static final int mix160_0(int x5, int x6, int x7)
	{
		return circularLeft((x5 & 0x01F80000)
			| (x6 & 0xFE000000) | (x7 & 0x0000003F), 13);
	}

	private static final int mix160_1(int x5, int x6, int x7)
	{
		return circularLeft((x5 & 0xFE000000)
			| (x6 & 0x0000003F) | (x7 & 0x00000FC0), 7);
	}

	private static final int mix160_2(int x5, int x6, int x7)
	{
		return (x5 & 0x0000003F)
			| (x6 & 0x00000FC0)
			| (x7 & 0x0007F000);
	}

	private static final int mix160_3(int x5, int x6, int x7)
	{
		return ((x5 & 0x00000FC0)
			| (x6 & 0x0007F000)
			| (x7 & 0x01F80000)) >>> 6;
	}

	private static final int mix160_4(int x5, int x6, int x7)
	{
		return ((x5 & 0x0007F000)
			| (x6 & 0x01F80000)
			| (x7 & 0xFE000000)) >>> 12;
	}

	private static final int mix192_0(int x6, int x7)
	{
		return circularLeft((x6 & 0xFC000000) | (x7 & 0x0000001F), 6);
	}

	private static final int mix192_1(int x6, int x7)
	{
		return (x6 & 0x0000001F) | (x7 & 0x000003E0);
	}

	private static final int mix192_2(int x6, int x7)
	{
		return ((x6 & 0x000003E0) | (x7 & 0x0000FC00)) >>> 5;
	}

	private static final int mix192_3(int x6, int x7)
	{
		return ((x6 & 0x0000FC00) | (x7 & 0x001F0000)) >>> 10;
	}

	private static final int mix192_4(int x6, int x7)
	{
		return ((x6 & 0x001F0000) | (x7 & 0x03E00000)) >>> 16;
	}

	private static final int mix192_5(int x6, int x7)
	{
		return ((x6 & 0x03E00000) | (x7 & 0xFC000000)) >>> 21;
	}

	private final void write128(byte[] out, int off)
	{
		encodeLEInt(s0 + mix128(s7, s4, s5, s6, 24), out, off);
		encodeLEInt(s1 + mix128(s6, s7, s4, s5, 16), out, off + 4);
		encodeLEInt(s2 + mix128(s5, s6, s7, s4,  8), out, off + 8);
		encodeLEInt(s3 + mix128(s4, s5, s6, s7,  0), out, off + 12);
	}

	private final void write160(byte[] out, int off)
	{
		encodeLEInt(s0 + mix160_0(s5, s6, s7), out, off);
		encodeLEInt(s1 + mix160_1(s5, s6, s7), out, off + 4);
		encodeLEInt(s2 + mix160_2(s5, s6, s7), out, off + 8);
		encodeLEInt(s3 + mix160_3(s5, s6, s7), out, off + 12);
		encodeLEInt(s4 + mix160_4(s5, s6, s7), out, off + 16);
	}

	private final void write192(byte[] out, int off)
	{
		encodeLEInt(s0 + mix192_0(s6, s7), out, off);
		encodeLEInt(s1 + mix192_1(s6, s7), out, off + 4);
		encodeLEInt(s2 + mix192_2(s6, s7), out, off + 8);
		encodeLEInt(s3 + mix192_3(s6, s7), out, off + 12);
		encodeLEInt(s4 + mix192_4(s6, s7), out, off + 16);
		encodeLEInt(s5 + mix192_5(s6, s7), out, off + 20);
	}

	private final void write224(byte[] out, int off)
	{
		encodeLEInt(s0 + ((s7 >>> 27) & 0x1F), out, off);
		encodeLEInt(s1 + ((s7 >>> 22) & 0x1F), out, off + 4);
		encodeLEInt(s2 + ((s7 >>> 18) & 0x0F), out, off + 8);
		encodeLEInt(s3 + ((s7 >>> 13) & 0x1F), out, off + 12);
		encodeLEInt(s4 + ((s7 >>>  9) & 0x0F), out, off + 16);
		encodeLEInt(s5 + ((s7 >>>  4) & 0x1F), out, off + 20);
		encodeLEInt(s6 + ((s7       ) & 0x0F), out, off + 24);
	}

	private final void write256(byte[] out, int off)
	{
		encodeLEInt(s0, out, off);
		encodeLEInt(s1, out, off + 4);
		encodeLEInt(s2, out, off + 8);
		encodeLEInt(s3, out, off + 12);
		encodeLEInt(s4, out, off + 16);
		encodeLEInt(s5, out, off + 20);
		encodeLEInt(s6, out, off + 24);
		encodeLEInt(s7, out, off + 28);
	}

	private final void writeOutput(byte[] out, int off)
	{
		switch (olen) {
		case 4:
			write128(out, off);
			break;
		case 5:
			write160(out, off);
			break;
		case 6:
			write192(out, off);
			break;
		case 7:
			write224(out, off);
			break;
		case 8:
			write256(out, off);
			break;
		}
	}

	/** @see Digest */
	public String toString()
	{
		return "HAVAL-" + passes + "-" + (olen << 5);
	}
}
