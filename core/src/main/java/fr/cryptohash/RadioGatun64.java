// $Id: RadioGatun64.java 232 2010-06-17 14:19:24Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the RadioGatun[64] digest algorithm under the
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
 * @version   $Revision: 232 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class RadioGatun64 extends DigestEngine {

	private long[] a, b;

	/**
	 * Build the object.
	 */
	public RadioGatun64()
	{
		super();
	}

	/** @see Digest */
	public Digest copy()
	{
		RadioGatun64 d = new RadioGatun64();
		System.arraycopy(a, 0, d.a, 0, a.length);
		System.arraycopy(b, 0, d.b, 0, b.length);
		return copyState(d);
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 32;
	}

	/** @see DigestEngine */
	protected int getInternalBlockLength()
	{
		return 312;
	}

	/** @see Digest */
	public int getBlockLength()
	{
		return -24;
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		for (int i = 0; i < a.length; i ++)
			a[i] = 0;
		for (int i = 0; i < b.length; i ++)
			b[i] = 0;
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		int ptr = flush();
		byte[] buf = getBlockBuffer();
		buf[ptr ++] = 0x01;
		for (int i = ptr; i < 312; i ++)
			buf[i] = 0;
		processBlock(buf);
		int num = 18;
		for (;;) {
			ptr += 24;
			if (ptr > 312)
				break;
			num --;
		}
		blank(num, output, outputOffset);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		a = new long[19];
		b = new long[39];
		engineReset();
	}

	/**
	 * Encode the 64-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in little-endian
	 * convention (least significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	private static final void encodeLELong(long val, byte[] buf, int off)
	{
		buf[off + 0] = (byte)val;
		buf[off + 1] = (byte)(val >>> 8);
		buf[off + 2] = (byte)(val >>> 16);
		buf[off + 3] = (byte)(val >>> 24);
		buf[off + 4] = (byte)(val >>> 32);
		buf[off + 5] = (byte)(val >>> 40);
		buf[off + 6] = (byte)(val >>> 48);
		buf[off + 7] = (byte)(val >>> 56);
	}

	/**
	 * Decode a 64-bit little-endian word from the array {@code buf}
	 * at offset {@code off}.
	 *
	 * @param buf   the source buffer
	 * @param off   the source offset
	 * @return  the decoded value
	 */
	private static final long decodeLELong(byte[] buf, int off)
	{
		return ((long)(buf[off + 7] & 0xFF) << 56)
			| ((long)(buf[off + 6] & 0xFF) << 48)
			| ((long)(buf[off + 5] & 0xFF) << 40)
			| ((long)(buf[off + 4] & 0xFF) << 32)
			| ((long)(buf[off + 3] & 0xFF) << 24)
			| ((long)(buf[off + 2] & 0xFF) << 16)
			| ((long)(buf[off + 1] & 0xFF) << 8)
			| (long)(buf[off] & 0xFF);
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		long a00 = a[ 0];
		long a01 = a[ 1];
		long a02 = a[ 2];
		long a03 = a[ 3];
		long a04 = a[ 4];
		long a05 = a[ 5];
		long a06 = a[ 6];
		long a07 = a[ 7];
		long a08 = a[ 8];
		long a09 = a[ 9];
		long a10 = a[10];
		long a11 = a[11];
		long a12 = a[12];
		long a13 = a[13];
		long a14 = a[14];
		long a15 = a[15];
		long a16 = a[16];
		long a17 = a[17];
		long a18 = a[18];

		int dp = 0;
		for (int mk = 12; mk >= 0; mk --) {
			long p0 = decodeLELong(data, dp + 0);
			long p1 = decodeLELong(data, dp + 8);
			long p2 = decodeLELong(data, dp + 16);
			dp += 24;
			int bj = (mk == 12) ? 0 : 3 * (mk + 1);
			b[bj + 0] ^= p0;
			b[bj + 1] ^= p1;
			b[bj + 2] ^= p2;
			a16 ^= p0;
			a17 ^= p1;
			a18 ^= p2;

			bj = mk * 3;
			if ((bj += 3) == 39)
				bj = 0;
			b[bj + 0] ^= a01;
			if ((bj += 3) == 39)
				bj = 0;
			b[bj + 1] ^= a02;
			if ((bj += 3) == 39)
				bj = 0;
			b[bj + 2] ^= a03;
			if ((bj += 3) == 39)
				bj = 0;
			b[bj + 0] ^= a04;
			if ((bj += 3) == 39)
				bj = 0;
			b[bj + 1] ^= a05;
			if ((bj += 3) == 39)
				bj = 0;
			b[bj + 2] ^= a06;
			if ((bj += 3) == 39)
				bj = 0;
			b[bj + 0] ^= a07;
			if ((bj += 3) == 39)
				bj = 0;
			b[bj + 1] ^= a08;
			if ((bj += 3) == 39)
				bj = 0;
			b[bj + 2] ^= a09;
			if ((bj += 3) == 39)
				bj = 0;
			b[bj + 0] ^= a10;
			if ((bj += 3) == 39)
				bj = 0;
			b[bj + 1] ^= a11;
			if ((bj += 3) == 39)
				bj = 0;
			b[bj + 2] ^= a12;

			long t00 = a00 ^ (a01 | ~a02);
			long t01 = a01 ^ (a02 | ~a03);
			long t02 = a02 ^ (a03 | ~a04);
			long t03 = a03 ^ (a04 | ~a05);
			long t04 = a04 ^ (a05 | ~a06);
			long t05 = a05 ^ (a06 | ~a07);
			long t06 = a06 ^ (a07 | ~a08);
			long t07 = a07 ^ (a08 | ~a09);
			long t08 = a08 ^ (a09 | ~a10);
			long t09 = a09 ^ (a10 | ~a11);
			long t10 = a10 ^ (a11 | ~a12);
			long t11 = a11 ^ (a12 | ~a13);
			long t12 = a12 ^ (a13 | ~a14);
			long t13 = a13 ^ (a14 | ~a15);
			long t14 = a14 ^ (a15 | ~a16);
			long t15 = a15 ^ (a16 | ~a17);
			long t16 = a16 ^ (a17 | ~a18);
			long t17 = a17 ^ (a18 | ~a00);
			long t18 = a18 ^ (a00 | ~a01);

			a00 = t00;
			a01 = (t07 << 63) | (t07 >>>  1);
			a02 = (t14 << 61) | (t14 >>>  3);
			a03 = (t02 << 58) | (t02 >>>  6);
			a04 = (t09 << 54) | (t09 >>> 10);
			a05 = (t16 << 49) | (t16 >>> 15);
			a06 = (t04 << 43) | (t04 >>> 21);
			a07 = (t11 << 36) | (t11 >>> 28);
			a08 = (t18 << 28) | (t18 >>> 36);
			a09 = (t06 << 19) | (t06 >>> 45);
			a10 = (t13 <<  9) | (t13 >>> 55);
			a11 = (t01 << 62) | (t01 >>>  2);
			a12 = (t08 << 50) | (t08 >>> 14);
			a13 = (t15 << 37) | (t15 >>> 27);
			a14 = (t03 << 23) | (t03 >>> 41);
			a15 = (t10 <<  8) | (t10 >>> 56);
			a16 = (t17 << 56) | (t17 >>>  8);
			a17 = (t05 << 39) | (t05 >>> 25);
			a18 = (t12 << 21) | (t12 >>> 43);

			t00 = a00 ^ a01 ^ a04;
			t01 = a01 ^ a02 ^ a05;
			t02 = a02 ^ a03 ^ a06;
			t03 = a03 ^ a04 ^ a07;
			t04 = a04 ^ a05 ^ a08;
			t05 = a05 ^ a06 ^ a09;
			t06 = a06 ^ a07 ^ a10;
			t07 = a07 ^ a08 ^ a11;
			t08 = a08 ^ a09 ^ a12;
			t09 = a09 ^ a10 ^ a13;
			t10 = a10 ^ a11 ^ a14;
			t11 = a11 ^ a12 ^ a15;
			t12 = a12 ^ a13 ^ a16;
			t13 = a13 ^ a14 ^ a17;
			t14 = a14 ^ a15 ^ a18;
			t15 = a15 ^ a16 ^ a00;
			t16 = a16 ^ a17 ^ a01;
			t17 = a17 ^ a18 ^ a02;
			t18 = a18 ^ a00 ^ a03;

			a00 = t00 ^ 1;
			a01 = t01;
			a02 = t02;
			a03 = t03;
			a04 = t04;
			a05 = t05;
			a06 = t06;
			a07 = t07;
			a08 = t08;
			a09 = t09;
			a10 = t10;
			a11 = t11;
			a12 = t12;
			a13 = t13;
			a14 = t14;
			a15 = t15;
			a16 = t16;
			a17 = t17;
			a18 = t18;

			bj = mk * 3;
			a13 ^= b[bj + 0];
			a14 ^= b[bj + 1];
			a15 ^= b[bj + 2];
		}

		a[ 0] = a00;
		a[ 1] = a01;
		a[ 2] = a02;
		a[ 3] = a03;
		a[ 4] = a04;
		a[ 5] = a05;
		a[ 6] = a06;
		a[ 7] = a07;
		a[ 8] = a08;
		a[ 9] = a09;
		a[10] = a10;
		a[11] = a11;
		a[12] = a12;
		a[13] = a13;
		a[14] = a14;
		a[15] = a15;
		a[16] = a16;
		a[17] = a17;
		a[18] = a18;
	}

	/**
	 * Run {@code num} blank rounds. For the last four rounds,
	 * {@code a[1]} and {@code a[2]} are written out in {@code out},
	 * beginning at offset {@code off}. This method does not write
	 * back all the state; thus, it must be the final operation in a
	 * given hash function computation.
	 *
	 * @param num   the number of blank rounds
	 * @param out   the output buffer
	 * @param off   the output offset
	 */
	private void blank(int num, byte[] out, int off)
	{
		long a00 = a[ 0];
		long a01 = a[ 1];
		long a02 = a[ 2];
		long a03 = a[ 3];
		long a04 = a[ 4];
		long a05 = a[ 5];
		long a06 = a[ 6];
		long a07 = a[ 7];
		long a08 = a[ 8];
		long a09 = a[ 9];
		long a10 = a[10];
		long a11 = a[11];
		long a12 = a[12];
		long a13 = a[13];
		long a14 = a[14];
		long a15 = a[15];
		long a16 = a[16];
		long a17 = a[17];
		long a18 = a[18];

		while (num -- > 0) {
			b[ 0] ^= a01;
			b[ 4] ^= a02;
			b[ 8] ^= a03;
			b[ 9] ^= a04;
			b[13] ^= a05;
			b[17] ^= a06;
			b[18] ^= a07;
			b[22] ^= a08;
			b[26] ^= a09;
			b[27] ^= a10;
			b[31] ^= a11;
			b[35] ^= a12;

			long t00 = a00 ^ (a01 | ~a02);
			long t01 = a01 ^ (a02 | ~a03);
			long t02 = a02 ^ (a03 | ~a04);
			long t03 = a03 ^ (a04 | ~a05);
			long t04 = a04 ^ (a05 | ~a06);
			long t05 = a05 ^ (a06 | ~a07);
			long t06 = a06 ^ (a07 | ~a08);
			long t07 = a07 ^ (a08 | ~a09);
			long t08 = a08 ^ (a09 | ~a10);
			long t09 = a09 ^ (a10 | ~a11);
			long t10 = a10 ^ (a11 | ~a12);
			long t11 = a11 ^ (a12 | ~a13);
			long t12 = a12 ^ (a13 | ~a14);
			long t13 = a13 ^ (a14 | ~a15);
			long t14 = a14 ^ (a15 | ~a16);
			long t15 = a15 ^ (a16 | ~a17);
			long t16 = a16 ^ (a17 | ~a18);
			long t17 = a17 ^ (a18 | ~a00);
			long t18 = a18 ^ (a00 | ~a01);

			a00 = t00;
			a01 = (t07 << 63) | (t07 >>>  1);
			a02 = (t14 << 61) | (t14 >>>  3);
			a03 = (t02 << 58) | (t02 >>>  6);
			a04 = (t09 << 54) | (t09 >>> 10);
			a05 = (t16 << 49) | (t16 >>> 15);
			a06 = (t04 << 43) | (t04 >>> 21);
			a07 = (t11 << 36) | (t11 >>> 28);
			a08 = (t18 << 28) | (t18 >>> 36);
			a09 = (t06 << 19) | (t06 >>> 45);
			a10 = (t13 <<  9) | (t13 >>> 55);
			a11 = (t01 << 62) | (t01 >>>  2);
			a12 = (t08 << 50) | (t08 >>> 14);
			a13 = (t15 << 37) | (t15 >>> 27);
			a14 = (t03 << 23) | (t03 >>> 41);
			a15 = (t10 <<  8) | (t10 >>> 56);
			a16 = (t17 << 56) | (t17 >>>  8);
			a17 = (t05 << 39) | (t05 >>> 25);
			a18 = (t12 << 21) | (t12 >>> 43);

			t00 = a00 ^ a01 ^ a04;
			t01 = a01 ^ a02 ^ a05;
			t02 = a02 ^ a03 ^ a06;
			t03 = a03 ^ a04 ^ a07;
			t04 = a04 ^ a05 ^ a08;
			t05 = a05 ^ a06 ^ a09;
			t06 = a06 ^ a07 ^ a10;
			t07 = a07 ^ a08 ^ a11;
			t08 = a08 ^ a09 ^ a12;
			t09 = a09 ^ a10 ^ a13;
			t10 = a10 ^ a11 ^ a14;
			t11 = a11 ^ a12 ^ a15;
			t12 = a12 ^ a13 ^ a16;
			t13 = a13 ^ a14 ^ a17;
			t14 = a14 ^ a15 ^ a18;
			t15 = a15 ^ a16 ^ a00;
			t16 = a16 ^ a17 ^ a01;
			t17 = a17 ^ a18 ^ a02;
			t18 = a18 ^ a00 ^ a03;

			a00 = t00 ^ 1;
			a01 = t01;
			a02 = t02;
			a03 = t03;
			a04 = t04;
			a05 = t05;
			a06 = t06;
			a07 = t07;
			a08 = t08;
			a09 = t09;
			a10 = t10;
			a11 = t11;
			a12 = t12;
			a13 = t13;
			a14 = t14;
			a15 = t15;
			a16 = t16;
			a17 = t17;
			a18 = t18;

			long bt0 = b[36];
			long bt1 = b[37];
			long bt2 = b[38];
			a13 ^= bt0;
			a14 ^= bt1;
			a15 ^= bt2;
			System.arraycopy(b, 0, b, 3, 36);
			b[0] = bt0;
			b[1] = bt1;
			b[2] = bt2;
			if (num < 2) {
				encodeLELong(a01, out, off + 0);
				encodeLELong(a02, out, off + 8);
				off += 16;
			}
		}

		/* not needed
		a[ 0] = a00;
		a[ 1] = a01;
		a[ 2] = a02;
		a[ 3] = a03;
		a[ 4] = a04;
		a[ 5] = a05;
		a[ 6] = a06;
		a[ 7] = a07;
		a[ 8] = a08;
		a[ 9] = a09;
		a[10] = a10;
		a[11] = a11;
		a[12] = a12;
		a[13] = a13;
		a[14] = a14;
		a[15] = a15;
		a[16] = a16;
		a[17] = a17;
		a[18] = a18;
		*/
	}

	/** @see Digest */
	public String toString()
	{
		return "RadioGatun[64]";
	}
}
