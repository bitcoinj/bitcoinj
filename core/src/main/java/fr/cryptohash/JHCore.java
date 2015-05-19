// $Id: JHCore.java 255 2011-06-07 19:50:20Z tp $

package fr.cryptohash;

/**
 * This class implements the core operations for the JH digest
 * algorithm.
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
 * @version   $Revision: 255 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class JHCore extends DigestEngine {

	JHCore()
	{
	}

	private long[] h;
	private byte[] tmpBuf;

	private static final long[] C = {
		0x72d5dea2df15f867L, 0x7b84150ab7231557L,
		0x81abd6904d5a87f6L, 0x4e9f4fc5c3d12b40L,
		0xea983ae05c45fa9cL, 0x03c5d29966b2999aL,
		0x660296b4f2bb538aL, 0xb556141a88dba231L,
		0x03a35a5c9a190edbL, 0x403fb20a87c14410L,
		0x1c051980849e951dL, 0x6f33ebad5ee7cddcL,
		0x10ba139202bf6b41L, 0xdc786515f7bb27d0L,
		0x0a2c813937aa7850L, 0x3f1abfd2410091d3L,
		0x422d5a0df6cc7e90L, 0xdd629f9c92c097ceL,
		0x185ca70bc72b44acL, 0xd1df65d663c6fc23L,
		0x976e6c039ee0b81aL, 0x2105457e446ceca8L,
		0xeef103bb5d8e61faL, 0xfd9697b294838197L,
		0x4a8e8537db03302fL, 0x2a678d2dfb9f6a95L,
		0x8afe7381f8b8696cL, 0x8ac77246c07f4214L,
		0xc5f4158fbdc75ec4L, 0x75446fa78f11bb80L,
		0x52de75b7aee488bcL, 0x82b8001e98a6a3f4L,
		0x8ef48f33a9a36315L, 0xaa5f5624d5b7f989L,
		0xb6f1ed207c5ae0fdL, 0x36cae95a06422c36L,
		0xce2935434efe983dL, 0x533af974739a4ba7L,
		0xd0f51f596f4e8186L, 0x0e9dad81afd85a9fL,
		0xa7050667ee34626aL, 0x8b0b28be6eb91727L,
		0x47740726c680103fL, 0xe0a07e6fc67e487bL,
		0x0d550aa54af8a4c0L, 0x91e3e79f978ef19eL,
		0x8676728150608dd4L, 0x7e9e5a41f3e5b062L,
		0xfc9f1fec4054207aL, 0xe3e41a00cef4c984L,
		0x4fd794f59dfa95d8L, 0x552e7e1124c354a5L,
		0x5bdf7228bdfe6e28L, 0x78f57fe20fa5c4b2L,
		0x05897cefee49d32eL, 0x447e9385eb28597fL,
		0x705f6937b324314aL, 0x5e8628f11dd6e465L,
		0xc71b770451b920e7L, 0x74fe43e823d4878aL,
		0x7d29e8a3927694f2L, 0xddcb7a099b30d9c1L,
		0x1d1b30fb5bdc1be0L, 0xda24494ff29c82bfL,
		0xa4e7ba31b470bfffL, 0x0d324405def8bc48L,
		0x3baefc3253bbd339L, 0x459fc3c1e0298ba0L,
		0xe5c905fdf7ae090fL, 0x947034124290f134L,
		0xa271b701e344ed95L, 0xe93b8e364f2f984aL,
		0x88401d63a06cf615L, 0x47c1444b8752afffL,
		0x7ebb4af1e20ac630L, 0x4670b6c5cc6e8ce6L,
		0xa4d5a456bd4fca00L, 0xda9d844bc83e18aeL,
		0x7357ce453064d1adL, 0xe8a6ce68145c2567L,
		0xa3da8cf2cb0ee116L, 0x33e906589a94999aL,
		0x1f60b220c26f847bL, 0xd1ceac7fa0d18518L,
		0x32595ba18ddd19d3L, 0x509a1cc0aaa5b446L,
		0x9f3d6367e4046bbaL, 0xf6ca19ab0b56ee7eL,
		0x1fb179eaa9282174L, 0xe9bdf7353b3651eeL,
		0x1d57ac5a7550d376L, 0x3a46c2fea37d7001L,
		0xf735c1af98a4d842L, 0x78edec209e6b6779L,
		0x41836315ea3adba8L, 0xfac33b4d32832c83L,
		0xa7403b1f1c2747f3L, 0x5940f034b72d769aL,
		0xe73e4e6cd2214ffdL, 0xb8fd8d39dc5759efL,
		0x8d9b0c492b49ebdaL, 0x5ba2d74968f3700dL,
		0x7d3baed07a8d5584L, 0xf5a5e9f0e4f88e65L,
		0xa0b8a2f436103b53L, 0x0ca8079e753eec5aL,
		0x9168949256e8884fL, 0x5bb05c55f8babc4cL,
		0xe3bb3b99f387947bL, 0x75daf4d6726b1c5dL,
		0x64aeac28dc34b36dL, 0x6c34a550b828db71L,
		0xf861e2f2108d512aL, 0xe3db643359dd75fcL,
		0x1cacbcf143ce3fa2L, 0x67bbd13c02e843b0L,
		0x330a5bca8829a175L, 0x7f34194db416535cL,
		0x923b94c30e794d1eL, 0x797475d7b6eeaf3fL,
		0xeaa8d4f7be1a3921L, 0x5cf47e094c232751L,
		0x26a32453ba323cd2L, 0x44a3174a6da6d5adL,
		0xb51d3ea6aff2c908L, 0x83593d98916b3c56L,
		0x4cf87ca17286604dL, 0x46e23ecc086ec7f6L,
		0x2f9833b3b1bc765eL, 0x2bd666a5efc4e62aL,
		0x06f4b6e8bec1d436L, 0x74ee8215bcef2163L,
		0xfdc14e0df453c969L, 0xa77d5ac406585826L,
		0x7ec1141606e0fa16L, 0x7e90af3d28639d3fL,
		0xd2c9f2e3009bd20cL, 0x5faace30b7d40c30L,
		0x742a5116f2e03298L, 0x0deb30d8e3cef89aL,
		0x4bc59e7bb5f17992L, 0xff51e66e048668d3L,
		0x9b234d57e6966731L, 0xcce6a6f3170a7505L,
		0xb17681d913326cceL, 0x3c175284f805a262L,
		0xf42bcbb378471547L, 0xff46548223936a48L,
		0x38df58074e5e6565L, 0xf2fc7c89fc86508eL,
		0x31702e44d00bca86L, 0xf04009a23078474eL,
		0x65a0ee39d1f73883L, 0xf75ee937e42c3abdL,
		0x2197b2260113f86fL, 0xa344edd1ef9fdee7L,
		0x8ba0df15762592d9L, 0x3c85f7f612dc42beL,
		0xd8a7ec7cab27b07eL, 0x538d7ddaaa3ea8deL,
		0xaa25ce93bd0269d8L, 0x5af643fd1a7308f9L,
		0xc05fefda174a19a5L, 0x974d66334cfd216aL,
		0x35b49831db411570L, 0xea1e0fbbedcd549bL,
		0x9ad063a151974072L, 0xf6759dbf91476fe2L
	};

	/**
	 * Encode the 64-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in big-endian
	 * convention (least significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	static private final void encodeBELong(long val, byte[] buf, int off)
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
	static private final long decodeBELong(byte[] buf, int off)
	{
		return ((buf[off + 0] & 0xFFL) << 56)
			| ((buf[off + 1] & 0xFFL) << 48)
			| ((buf[off + 2] & 0xFFL) << 40)
			| ((buf[off + 3] & 0xFFL) << 32)
			| ((buf[off + 4] & 0xFFL) << 24)
			| ((buf[off + 5] & 0xFFL) << 16)
			| ((buf[off + 6] & 0xFFL) << 8)
			| (buf[off + 7] & 0xFFL);
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		doReset();
	}

	private final void doS(int r)
	{
		long x0, x1, x2, x3, cc, tmp;

		cc = C[(r << 2) + 0];
		x0 = h[ 0];
		x1 = h[ 4];
		x2 = h[ 8];
		x3 = h[12];
		x3 = ~x3;
		x0 ^= cc & ~x2;
		tmp = cc ^ (x0 & x1);
		x0 ^= x2 & x3;
		x3 ^= ~x1 & x2;
		x1 ^= x0 & x2;
		x2 ^= x0 & ~x3;
		x0 ^= x1 | x3;
		x3 ^= x1 & x2;
		x1 ^= tmp & x0;
		x2 ^= tmp;
		h[ 0] = x0;
		h[ 4] = x1;
		h[ 8] = x2;
		h[12] = x3;

		cc = C[(r << 2) + 1];
		x0 = h[ 1];
		x1 = h[ 5];
		x2 = h[ 9];
		x3 = h[13];
		x3 = ~x3;
		x0 ^= cc & ~x2;
		tmp = cc ^ (x0 & x1);
		x0 ^= x2 & x3;
		x3 ^= ~x1 & x2;
		x1 ^= x0 & x2;
		x2 ^= x0 & ~x3;
		x0 ^= x1 | x3;
		x3 ^= x1 & x2;
		x1 ^= tmp & x0;
		x2 ^= tmp;
		h[ 1] = x0;
		h[ 5] = x1;
		h[ 9] = x2;
		h[13] = x3;

		cc = C[(r << 2) + 2];
		x0 = h[ 2];
		x1 = h[ 6];
		x2 = h[10];
		x3 = h[14];
		x3 = ~x3;
		x0 ^= cc & ~x2;
		tmp = cc ^ (x0 & x1);
		x0 ^= x2 & x3;
		x3 ^= ~x1 & x2;
		x1 ^= x0 & x2;
		x2 ^= x0 & ~x3;
		x0 ^= x1 | x3;
		x3 ^= x1 & x2;
		x1 ^= tmp & x0;
		x2 ^= tmp;
		h[ 2] = x0;
		h[ 6] = x1;
		h[10] = x2;
		h[14] = x3;

		cc = C[(r << 2) + 3];
		x0 = h[ 3];
		x1 = h[ 7];
		x2 = h[11];
		x3 = h[15];
		x3 = ~x3;
		x0 ^= cc & ~x2;
		tmp = cc ^ (x0 & x1);
		x0 ^= x2 & x3;
		x3 ^= ~x1 & x2;
		x1 ^= x0 & x2;
		x2 ^= x0 & ~x3;
		x0 ^= x1 | x3;
		x3 ^= x1 & x2;
		x1 ^= tmp & x0;
		x2 ^= tmp;
		h[ 3] = x0;
		h[ 7] = x1;
		h[11] = x2;
		h[15] = x3;
	}

	private final void doL()
	{
		long x0, x1, x2, x3, x4, x5, x6, x7;
		x0 = h[ 0];
		x1 = h[ 4];
		x2 = h[ 8];
		x3 = h[12];
		x4 = h[ 2];
		x5 = h[ 6];
		x6 = h[10];
		x7 = h[14];
		x4 ^= x1;
		x5 ^= x2;
		x6 ^= x3 ^ x0;
		x7 ^= x0;
		x0 ^= x5;
		x1 ^= x6;
		x2 ^= x7 ^ x4;
		x3 ^= x4;
		h[ 0] = x0;
		h[ 4] = x1;
		h[ 8] = x2;
		h[12] = x3;
		h[ 2] = x4;
		h[ 6] = x5;
		h[10] = x6;
		h[14] = x7;

		x0 = h[ 1];
		x1 = h[ 5];
		x2 = h[ 9];
		x3 = h[13];
		x4 = h[ 3];
		x5 = h[ 7];
		x6 = h[11];
		x7 = h[15];
		x4 ^= x1;
		x5 ^= x2;
		x6 ^= x3 ^ x0;
		x7 ^= x0;
		x0 ^= x5;
		x1 ^= x6;
		x2 ^= x7 ^ x4;
		x3 ^= x4;
		h[ 1] = x0;
		h[ 5] = x1;
		h[ 9] = x2;
		h[13] = x3;
		h[ 3] = x4;
		h[ 7] = x5;
		h[11] = x6;
		h[15] = x7;
	}

	private final void doWgen(long c, int n)
	{
		h[ 2] = ((h[ 2] & c) << n) | ((h[ 2] >>> n) & c);
		h[ 3] = ((h[ 3] & c) << n) | ((h[ 3] >>> n) & c);
		h[ 6] = ((h[ 6] & c) << n) | ((h[ 6] >>> n) & c);
		h[ 7] = ((h[ 7] & c) << n) | ((h[ 7] >>> n) & c);
		h[10] = ((h[10] & c) << n) | ((h[10] >>> n) & c);
		h[11] = ((h[11] & c) << n) | ((h[11] >>> n) & c);
		h[14] = ((h[14] & c) << n) | ((h[14] >>> n) & c);
		h[15] = ((h[15] & c) << n) | ((h[15] >>> n) & c);
	}

	private final void doW6()
	{
		long t;
		t = h[ 2]; h[ 2] = h[ 3]; h[ 3] = t;
		t = h[ 6]; h[ 6] = h[ 7]; h[ 7] = t;
		t = h[10]; h[10] = h[11]; h[11] = t;
		t = h[14]; h[14] = h[15]; h[15] = t;
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		long m0h = decodeBELong(data,  0);
		long m0l = decodeBELong(data,  8);
		long m1h = decodeBELong(data, 16);
		long m1l = decodeBELong(data, 24);
		long m2h = decodeBELong(data, 32);
		long m2l = decodeBELong(data, 40);
		long m3h = decodeBELong(data, 48);
		long m3l = decodeBELong(data, 56);
		h[0] ^= m0h;
		h[1] ^= m0l;
		h[2] ^= m1h;
		h[3] ^= m1l;
		h[4] ^= m2h;
		h[5] ^= m2l;
		h[6] ^= m3h;
		h[7] ^= m3l;
		for (int r = 0; r < 42; r += 7) {
			doS(r + 0);
			doL();
			doWgen(0x5555555555555555L,  1);
			doS(r + 1);
			doL();
			doWgen(0x3333333333333333L,  2);
			doS(r + 2);
			doL();
			doWgen(0x0F0F0F0F0F0F0F0FL,  4);
			doS(r + 3);
			doL();
			doWgen(0x00FF00FF00FF00FFL,  8);
			doS(r + 4);
			doL();
			doWgen(0x0000FFFF0000FFFFL, 16);
			doS(r + 5);
			doL();
			doWgen(0x00000000FFFFFFFFL, 32);
			doS(r + 6);
			doL();
			doW6();
		}
		h[ 8] ^= m0h;
		h[ 9] ^= m0l;
		h[10] ^= m1h;
		h[11] ^= m1l;
		h[12] ^= m2h;
		h[13] ^= m2l;
		h[14] ^= m3h;
		h[15] ^= m3l;
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] buf, int off)
	{
		int rem = flush();
		long bc = getBlockCount();
		int numz = (rem == 0) ? 47 : 111 - rem;
		tmpBuf[0] = (byte)0x80;
		for (int i = 1; i <= numz; i ++)
			tmpBuf[i] = 0x00;
		encodeBELong(bc >>> 55, tmpBuf, numz + 1);
		encodeBELong((bc << 9) + (rem << 3), tmpBuf, numz + 9);
		update(tmpBuf, 0, numz + 17);
		for (int i = 0; i < 8; i ++)
			encodeBELong(h[i + 8], tmpBuf, i << 3);
		int dlen = getDigestLength();
		System.arraycopy(tmpBuf, 64 - dlen, buf, off, dlen);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		h = new long[16];
		tmpBuf = new byte[128];
		doReset();
	}

	/**
	 * Get the initial values.
	 *
	 * @return  the IV
	 */
	abstract long[] getIV();

	/** @see Digest */
	public int getBlockLength()
	{
		return 64;
	}

	private final void doReset()
	{
		System.arraycopy(getIV(), 0, h, 0, 16);
	}

	/** @see DigestEngine */
	protected Digest copyState(JHCore dst)
	{
		System.arraycopy(h, 0, dst.h, 0, 16);
		return super.copyState(dst);
	}

	/** @see Digest */
	public String toString()
	{
		return "JH-" + (getDigestLength() << 3);
	}
}
