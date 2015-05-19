// $Id: PANAMA.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * This class implements the PANAMA digest algorithm under the
 * {@link Digest} API.
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

public class PANAMA extends DigestEngine {

	/**
	 * Create the object.
	 */
	public PANAMA()
	{
	}

	private int[] buffer;
	private int bufferPtr;
	private int state0, state1, state2, state3, state4, state5;
	private int state6, state7, state8, state9, state10, state11;
	private int state12, state13, state14, state15, state16;
	private int inData0, inData1, inData2, inData3;
	private int inData4, inData5, inData6, inData7;

	/** @see Digest */
	public Digest copy()
	{
		PANAMA d = new PANAMA();
		System.arraycopy(buffer, 0, d.buffer, 0, buffer.length);
		d.bufferPtr = bufferPtr;
		d.state0  = state0 ;
		d.state1  = state1 ;
		d.state2  = state2 ;
		d.state3  = state3 ;
		d.state4  = state4 ;
		d.state5  = state5 ;
		d.state6  = state6 ;
		d.state7  = state7 ;
		d.state8  = state8 ;
		d.state9  = state9 ;
		d.state10 = state10;
		d.state11 = state11;
		d.state12 = state12;
		d.state13 = state13;
		d.state14 = state14;
		d.state15 = state15;
		d.state16 = state16;
		return copyState(d);
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 32;
	}

	/** @see Digest */
	public int getBlockLength()
	{
		return 32;
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		for (int i = 0; i < buffer.length; i ++)
			buffer[i] = 0;
		bufferPtr = 0;
		state0  = 0;
		state1  = 0;
		state2  = 0;
		state3  = 0;
		state4  = 0;
		state5  = 0;
		state6  = 0;
		state7  = 0;
		state8  = 0;
		state9  = 0;
		state10 = 0;
		state11 = 0;
		state12 = 0;
		state13 = 0;
		state14 = 0;
		state15 = 0;
		state16 = 0;
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		int pending = flush();
		update((byte)0x01);
		for (int i = pending + 1; i < 32; i ++)
			update((byte)0x00);
		flush();
		for (int i = 0; i < 32; i ++)
			oneStep(false);
		encodeLEInt(state9,  output, outputOffset + 0);
		encodeLEInt(state10, output, outputOffset + 4);
		encodeLEInt(state11, output, outputOffset + 8);
		encodeLEInt(state12, output, outputOffset + 12);
		encodeLEInt(state13, output, outputOffset + 16);
		encodeLEInt(state14, output, outputOffset + 20);
		encodeLEInt(state15, output, outputOffset + 24);
		encodeLEInt(state16, output, outputOffset + 28);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		buffer = new int[256];
		/*
		 * engineReset() is not needed because in Java, "int"
		 * variables and arrays of "int" are initialized upon
		 * creation to the correct value (full of zeroes).
		 */
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

	/**
	 * Decode a 32-bit little-endian word from the array {@code buf}
	 * at offset {@code off}.
	 *
	 * @param buf   the source buffer
	 * @param off   the source offset
	 * @return  the decoded value
	 */
	static private final int decodeLEInt(byte[] buf, int off)
	{
		return (buf[off] & 0xFF)
			| ((buf[off + 1] & 0xFF) << 8)
			| ((buf[off + 2] & 0xFF) << 16)
			| ((buf[off + 3] & 0xFF) << 24);
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		inData0 = decodeLEInt(data, 0);
		inData1 = decodeLEInt(data, 4);
		inData2 = decodeLEInt(data, 8);
		inData3 = decodeLEInt(data, 12);
		inData4 = decodeLEInt(data, 16);
		inData5 = decodeLEInt(data, 20);
		inData6 = decodeLEInt(data, 24);
		inData7 = decodeLEInt(data, 28);
		oneStep(true);
	}

	private final void oneStep(boolean push)
	{
		/*
		 * Buffer update.
		 */
		int ptr0 = bufferPtr;
		int ptr24 = (ptr0 - 64) & 248;
		int ptr31 = (ptr0 - 8) & 248;
		if (push) {
			buffer[ptr24 + 0] ^= buffer[ptr31 + 2];
			buffer[ptr31 + 2] ^= inData2;
			buffer[ptr24 + 1] ^= buffer[ptr31 + 3];
			buffer[ptr31 + 3] ^= inData3;
			buffer[ptr24 + 2] ^= buffer[ptr31 + 4];
			buffer[ptr31 + 4] ^= inData4;
			buffer[ptr24 + 3] ^= buffer[ptr31 + 5];
			buffer[ptr31 + 5] ^= inData5;
			buffer[ptr24 + 4] ^= buffer[ptr31 + 6];
			buffer[ptr31 + 6] ^= inData6;
			buffer[ptr24 + 5] ^= buffer[ptr31 + 7];
			buffer[ptr31 + 7] ^= inData7;
			buffer[ptr24 + 6] ^= buffer[ptr31 + 0];
			buffer[ptr31 + 0] ^= inData0;
			buffer[ptr24 + 7] ^= buffer[ptr31 + 1];
			buffer[ptr31 + 1] ^= inData1;
		} else {
			buffer[ptr24 + 0] ^= buffer[ptr31 + 2];
			buffer[ptr31 + 2] ^= state3;
			buffer[ptr24 + 1] ^= buffer[ptr31 + 3];
			buffer[ptr31 + 3] ^= state4;
			buffer[ptr24 + 2] ^= buffer[ptr31 + 4];
			buffer[ptr31 + 4] ^= state5;
			buffer[ptr24 + 3] ^= buffer[ptr31 + 5];
			buffer[ptr31 + 5] ^= state6;
			buffer[ptr24 + 4] ^= buffer[ptr31 + 6];
			buffer[ptr31 + 6] ^= state7;
			buffer[ptr24 + 5] ^= buffer[ptr31 + 7];
			buffer[ptr31 + 7] ^= state8;
			buffer[ptr24 + 6] ^= buffer[ptr31 + 0];
			buffer[ptr31 + 0] ^= state1;
			buffer[ptr24 + 7] ^= buffer[ptr31 + 1];
			buffer[ptr31 + 1] ^= state2;
		}
		bufferPtr = ptr31;

		/*
		 * Gamma transform.
		 */
		int g0, g1, g2, g3, g4, g5, g6, g7, g8, g9;
		int g10, g11, g12, g13, g14, g15, g16;
		g0  = state0  ^ (state1  | ~state2 );
		g1  = state1  ^ (state2  | ~state3 );
		g2  = state2  ^ (state3  | ~state4 );
		g3  = state3  ^ (state4  | ~state5 );
		g4  = state4  ^ (state5  | ~state6 );
		g5  = state5  ^ (state6  | ~state7 );
		g6  = state6  ^ (state7  | ~state8 );
		g7  = state7  ^ (state8  | ~state9 );
		g8  = state8  ^ (state9  | ~state10);
		g9  = state9  ^ (state10 | ~state11);
		g10 = state10 ^ (state11 | ~state12);
		g11 = state11 ^ (state12 | ~state13);
		g12 = state12 ^ (state13 | ~state14);
		g13 = state13 ^ (state14 | ~state15);
		g14 = state14 ^ (state15 | ~state16);
		g15 = state15 ^ (state16 | ~state0 );
		g16 = state16 ^ (state0  | ~state1 );

		/*
		 * Pi transform.
		 */
		int p0, p1, p2, p3, p4, p5, p6, p7, p8, p9;
		int p10, p11, p12, p13, p14, p15, p16;
		p0  = g0;
		p1  = ( g7 <<  1) | ( g7 >>> (32 -  1));
		p2  = (g14 <<  3) | (g14 >>> (32 -  3));
		p3  = ( g4 <<  6) | ( g4 >>> (32 -  6));
		p4  = (g11 << 10) | (g11 >>> (32 - 10));
		p5  = ( g1 << 15) | ( g1 >>> (32 - 15));
		p6  = ( g8 << 21) | ( g8 >>> (32 - 21));
		p7  = (g15 << 28) | (g15 >>> (32 - 28));
		p8  = ( g5 <<  4) | ( g5 >>> (32 -  4));
		p9  = (g12 << 13) | (g12 >>> (32 - 13));
		p10 = ( g2 << 23) | ( g2 >>> (32 - 23));
		p11 = ( g9 <<  2) | ( g9 >>> (32 -  2));
		p12 = (g16 << 14) | (g16 >>> (32 - 14));
		p13 = ( g6 << 27) | ( g6 >>> (32 - 27));
		p14 = (g13 <<  9) | (g13 >>> (32 -  9));
		p15 = ( g3 << 24) | ( g3 >>> (32 - 24));
		p16 = (g10 <<  8) | (g10 >>> (32 -  8));

		/*
		 * Theta transform.
		 */
		int t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
		int t10, t11, t12, t13, t14, t15, t16;
		t0  = p0  ^ p1  ^ p4 ;
		t1  = p1  ^ p2  ^ p5 ;
		t2  = p2  ^ p3  ^ p6 ;
		t3  = p3  ^ p4  ^ p7 ;
		t4  = p4  ^ p5  ^ p8 ;
		t5  = p5  ^ p6  ^ p9 ;
		t6  = p6  ^ p7  ^ p10;
		t7  = p7  ^ p8  ^ p11;
		t8  = p8  ^ p9  ^ p12;
		t9  = p9  ^ p10 ^ p13;
		t10 = p10 ^ p11 ^ p14;
		t11 = p11 ^ p12 ^ p15;
		t12 = p12 ^ p13 ^ p16;
		t13 = p13 ^ p14 ^ p0 ;
		t14 = p14 ^ p15 ^ p1 ;
		t15 = p15 ^ p16 ^ p2 ;
		t16 = p16 ^ p0  ^ p3 ;

		/*
		 * Sigma transform.
		 */
		int ptr16 = ptr0 ^ 128;
		state0 = t0 ^ 1;
		if (push) {
			state1 = t1 ^ inData0;
			state2 = t2 ^ inData1;
			state3 = t3 ^ inData2;
			state4 = t4 ^ inData3;
			state5 = t5 ^ inData4;
			state6 = t6 ^ inData5;
			state7 = t7 ^ inData6;
			state8 = t8 ^ inData7;
		} else {
			int ptr4 = (ptr0 + 32) & 248;
			state1 = t1 ^ buffer[ptr4 + 0];
			state2 = t2 ^ buffer[ptr4 + 1];
			state3 = t3 ^ buffer[ptr4 + 2];
			state4 = t4 ^ buffer[ptr4 + 3];
			state5 = t5 ^ buffer[ptr4 + 4];
			state6 = t6 ^ buffer[ptr4 + 5];
			state7 = t7 ^ buffer[ptr4 + 6];
			state8 = t8 ^ buffer[ptr4 + 7];
		}
		state9  = t9  ^ buffer[ptr16 + 0];
		state10 = t10 ^ buffer[ptr16 + 1];
		state11 = t11 ^ buffer[ptr16 + 2];
		state12 = t12 ^ buffer[ptr16 + 3];
		state13 = t13 ^ buffer[ptr16 + 4];
		state14 = t14 ^ buffer[ptr16 + 5];
		state15 = t15 ^ buffer[ptr16 + 6];
		state16 = t16 ^ buffer[ptr16 + 7];
	}

	/** @see Digest */
	public String toString()
	{
		return "PANAMA";
	}
}
