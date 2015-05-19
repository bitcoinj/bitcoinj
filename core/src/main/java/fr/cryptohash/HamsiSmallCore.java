// $Id: HamsiSmallCore.java 239 2010-06-21 14:58:08Z tp $

package fr.cryptohash;

/**
 * This class implements Hamsi-224 and Hamsi-256.
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
 * @version   $Revision: 239 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class HamsiSmallCore implements Digest {

	private int[] h;
	private long bitCount;
	private int partial;
	private int partialLen;

	/**
	 * Create the object.
	 */
	HamsiSmallCore()
	{
		h = new int[8];
		reset();
	}

	/** @see Digest */
	public void update(byte in)
	{
		bitCount += 8;
		partial = (partial << 8) | (in & 0xFF);
		partialLen ++;
		if (partialLen == 4) {
			process(partial >>> 24, (partial >>> 16) & 0xFF,
				(partial >>> 8) & 0xFF, partial & 0xFF);
			partialLen = 0;
		}
	}

	/** @see Digest */
	public void update(byte[] inbuf)
	{
		update(inbuf, 0, inbuf.length);
	}

	/** @see Digest */
	public void update(byte[] inbuf, int off, int len)
	{
		bitCount += (long)len << 3;
		if (partialLen != 0) {
			while (partialLen < 4 && len > 0) {
				partial = (partial << 8)
					| (inbuf[off ++] & 0xFF);
				partialLen ++;
				len --;
			}
			if (partialLen < 4)
				return;
			process(partial >>> 24, (partial >>> 16) & 0xFF,
				(partial >>> 8) & 0xFF, partial & 0xFF);
			partialLen = 0;
		}
		while (len >= 4) {
			process(inbuf[off + 0] & 0xFF,
				inbuf[off + 1] & 0xFF,
				inbuf[off + 2] & 0xFF,
				inbuf[off + 3] & 0xFF);
			off += 4;
			len -= 4;
		}
		partialLen = len;
		while (len -- > 0)
			partial = (partial << 8) | (inbuf[off ++] & 0xFF);
	}

	/** @see Digest */
	public byte[] digest()
	{
		int n = getDigestLength();
		byte[] out = new byte[n];
		digest(out, 0, n);
		return out;
	}

	/** @see Digest */
	public byte[] digest(byte[] inbuf)
	{
		update(inbuf, 0, inbuf.length);
		return digest();
	}

	/** @see Digest */
	public int digest(byte[] outbuf, int off, int len)
	{
		long bitCount = this.bitCount;
		update((byte)0x80);
		while (partialLen != 0)
			update((byte)0x00);
		process((int)(bitCount >>> 56) & 0xFF,
			(int)(bitCount >>> 48) & 0xFF,
			(int)(bitCount >>> 40) & 0xFF,
			(int)(bitCount >>> 32) & 0xFF);
		processFinal(((int)bitCount >>> 24) & 0xFF,
			((int)bitCount >>> 16) & 0xFF,
			((int)bitCount >>> 8) & 0xFF,
			(int)bitCount & 0xFF);
		int n = getDigestLength();
		if (len > n)
			len = n;
		int ch = 0;
		for (int i = 0, j = 0; i < len; i ++) {
			if ((i & 3) == 0)
				ch = h[j ++];
			outbuf[off + i] = (byte)(ch >>> 24);
			ch <<= 8;
		}
		reset();
		return len;
	}

	/** @see Digest */
	public void reset()
	{
		System.arraycopy(getIV(), 0, h, 0, h.length);
		bitCount = 0;
		partialLen = 0;
	}

	/** @see Digest */
	public Digest copy()
	{
		HamsiSmallCore d = dup();
		System.arraycopy(h, 0, d.h, 0, h.length);
		d.bitCount = bitCount;
		d.partial = partial;
		d.partialLen = partialLen;
		return d;
	}

	/** @see Digest */
	public int getBlockLength()
	{
		/*
		 * Private communication from Hamsi designer Ozgul Kucuk:
		 *
		 * << For HMAC you can calculate B = 256*ceil(k / 256)
		 *    (same as CubeHash). >>
		 */
		return -32;
	}

	/**
	 * Get the IV.
	 *
	 * @return  the IV (initial values for the state words)
	 */
	abstract int[] getIV();

	/**
	 * Create a new instance of the same runtime class than this object.
	 *
	 * @return  the duplicate
	 */
	abstract HamsiSmallCore dup();

	private static final int[][] Tsrc = {
		{ 0x045f0000, 0x9c4a93c9, 0x62fc79d0, 0x731ebdc2,
		  0xe0278000, 0x19dce008, 0xd7075d82, 0x5ad2e31d },
		{ 0xe4788000, 0x859673c1, 0xb5fb2452, 0x29cc5edf,
		  0x045f0000, 0x9c4a93c9, 0x62fc79d0, 0x731ebdc2 },
		{ 0xe6570000, 0x4bb33a25, 0x848598ba, 0x1041003e,
		  0xf44c4000, 0x10a4e3cd, 0x097f5711, 0xde77cc4c },
		{ 0x121b4000, 0x5b17d9e8, 0x8dfacfab, 0xce36cc72,
		  0xe6570000, 0x4bb33a25, 0x848598ba, 0x1041003e },
		{ 0x97530000, 0x204f6ed3, 0x77b9e80f, 0xa1ec5ec1,
		  0x7e792000, 0x9418e22f, 0x6643d258, 0x9c255be5 },
		{ 0xe92a2000, 0xb4578cfc, 0x11fa3a57, 0x3dc90524,
		  0x97530000, 0x204f6ed3, 0x77b9e80f, 0xa1ec5ec1 },
		{ 0xcba90000, 0x90273769, 0xbbdcf407, 0xd0f4af61,
		  0xbf3c1000, 0xca0c7117, 0x3321e92c, 0xce122df3 },
		{ 0x74951000, 0x5a2b467e, 0x88fd1d2b, 0x1ee68292,
		  0xcba90000, 0x90273769, 0xbbdcf407, 0xd0f4af61 },
		{ 0xe18b0000, 0x5459887d, 0xbf1283d3, 0x1b666a73,
		  0x3fb90800, 0x7cdad883, 0xce97a914, 0xbdd9f5e5 },
		{ 0xde320800, 0x288350fe, 0x71852ac7, 0xa6bf9f96,
		  0xe18b0000, 0x5459887d, 0xbf1283d3, 0x1b666a73 },
		{ 0x14bd0000, 0x2fba37ff, 0x6a72e5bb, 0x247febe6,
		  0x9b830400, 0x2227ff88, 0x05b7ad5a, 0xadf2c730 },
		{ 0x8f3e0400, 0x0d9dc877, 0x6fc548e1, 0x898d2cd6,
		  0x14bd0000, 0x2fba37ff, 0x6a72e5bb, 0x247febe6 },
		{ 0xee260000, 0x124b683e, 0x80c2d68f, 0x3bf3ab2c,
		  0x499e0200, 0x0d59ec0d, 0xe0272f7d, 0xa5e7de5a },
		{ 0xa7b80200, 0x1f128433, 0x60e5f9f2, 0x9e147576,
		  0xee260000, 0x124b683e, 0x80c2d68f, 0x3bf3ab2c },
		{ 0x734c0000, 0x956fa7d6, 0xa29d1297, 0x6ee56854,
		  0xc4e80100, 0x1f70960e, 0x2714ca3c, 0x88210c30 },
		{ 0xb7a40100, 0x8a1f31d8, 0x8589d8ab, 0xe6c46464,
		  0x734c0000, 0x956fa7d6, 0xa29d1297, 0x6ee56854 },
		{ 0x39a60000, 0x4ab753eb, 0xd14e094b, 0xb772b42b,
		  0x62740080, 0x0fb84b07, 0x138a651e, 0x44100618 },
		{ 0x5bd20080, 0x450f18ec, 0xc2c46c55, 0xf362b233,
		  0x39a60000, 0x4ab753eb, 0xd14e094b, 0xb772b42b },
		{ 0x78ab0000, 0xa0cd5a34, 0x5d5ca0f7, 0x727784cb,
		  0x35650040, 0x9b96b64a, 0x6b39cb5f, 0x5114bece },
		{ 0x4dce0040, 0x3b5bec7e, 0x36656ba8, 0x23633a05,
		  0x78ab0000, 0xa0cd5a34, 0x5d5ca0f7, 0x727784cb },
		{ 0x5c720000, 0xc9bacd12, 0x79a90df9, 0x63e92178,
		  0xfeca0020, 0x485d28e4, 0x806741fd, 0x814681b8 },
		{ 0xa2b80020, 0x81e7e5f6, 0xf9ce4c04, 0xe2afa0c0,
		  0x5c720000, 0xc9bacd12, 0x79a90df9, 0x63e92178 },
		{ 0x2e390000, 0x64dd6689, 0x3cd406fc, 0xb1f490bc,
		  0x7f650010, 0x242e1472, 0xc03320fe, 0xc0a3c0dd },
		{ 0x515c0010, 0x40f372fb, 0xfce72602, 0x71575061,
		  0x2e390000, 0x64dd6689, 0x3cd406fc, 0xb1f490bc },
		{ 0x171c0000, 0xb26e3344, 0x9e6a837e, 0x58f8485f,
		  0xbfb20008, 0x92170a39, 0x6019107f, 0xe051606e },
		{ 0xa8ae0008, 0x2079397d, 0xfe739301, 0xb8a92831,
		  0x171c0000, 0xb26e3344, 0x9e6a837e, 0x58f8485f },
		{ 0x6ba90000, 0x40ebf9aa, 0x98321c3d, 0x76acc733,
		  0xbba10004, 0xcc9d76dd, 0x05f7ac6d, 0xd9e6eee9 },
		{ 0xd0080004, 0x8c768f77, 0x9dc5b050, 0xaf4a29da,
		  0x6ba90000, 0x40ebf9aa, 0x98321c3d, 0x76acc733 },
		{ 0x51ac0000, 0x25e30f14, 0x79e22a4c, 0x1298bd46,
		  0xd98f0002, 0x7a04a8a7, 0xe007afe6, 0x9fed4ab7 },
		{ 0x88230002, 0x5fe7a7b3, 0x99e585aa, 0x8d75f7f1,
		  0x51ac0000, 0x25e30f14, 0x79e22a4c, 0x1298bd46 },
		{ 0xc8f10000, 0x0b2de782, 0x6bf648a4, 0x539cbdbf,
		  0x08bf0001, 0x38942792, 0xc5f8f3a1, 0xe6387b84 },
		{ 0xc04e0001, 0x33b9c010, 0xae0ebb05, 0xb5a4c63b,
		  0xc8f10000, 0x0b2de782, 0x6bf648a4, 0x539cbdbf }
	};

	private static int[][] makeT(int x)
	{
		int[][] T = new int[256][8];
		for (int y = 0; y < 256; y ++) {
			for (int z = 0; z < 8; z ++) {
				int a = 0;
				for (int k = 0; k < 8; k ++) {
					if ((y & (1 << (7 - k))) != 0)
						a ^= Tsrc[x + k][z];
				}
				T[y][z] = a;
			}
		}
		return T;
	}

	private static final int[][] T256_0 = makeT(0);
	private static final int[][] T256_1 = makeT(8);
	private static final int[][] T256_2 = makeT(16);
	private static final int[][] T256_3 = makeT(24);

	private static final int[] ALPHA_N = {
		0xff00f0f0, 0xccccaaaa, 0xf0f0cccc, 0xff00aaaa,
		0xccccaaaa, 0xf0f0ff00, 0xaaaacccc, 0xf0f0ff00,
		0xf0f0cccc, 0xaaaaff00, 0xccccff00, 0xaaaaf0f0,
		0xaaaaf0f0, 0xff00cccc, 0xccccf0f0, 0xff00aaaa,
		0xccccaaaa, 0xff00f0f0, 0xff00aaaa, 0xf0f0cccc,
		0xf0f0ff00, 0xccccaaaa, 0xf0f0ff00, 0xaaaacccc,
		0xaaaaff00, 0xf0f0cccc, 0xaaaaf0f0, 0xccccff00,
		0xff00cccc, 0xaaaaf0f0, 0xff00aaaa, 0xccccf0f0
	};

	private static final int[] ALPHA_F = {
		0xcaf9639c, 0x0ff0f9c0, 0x639c0ff0, 0xcaf9f9c0,
		0x0ff0f9c0, 0x639ccaf9, 0xf9c00ff0, 0x639ccaf9,
		0x639c0ff0, 0xf9c0caf9, 0x0ff0caf9, 0xf9c0639c,
		0xf9c0639c, 0xcaf90ff0, 0x0ff0639c, 0xcaf9f9c0,
		0x0ff0f9c0, 0xcaf9639c, 0xcaf9f9c0, 0x639c0ff0,
		0x639ccaf9, 0x0ff0f9c0, 0x639ccaf9, 0xf9c00ff0,
		0xf9c0caf9, 0x639c0ff0, 0xf9c0639c, 0x0ff0caf9,
		0xcaf90ff0, 0xf9c0639c, 0xcaf9f9c0, 0x0ff0639c
	};

	private void process(int b0, int b1, int b2, int b3)
	{
		int[] rp = T256_0[b0];
		int m0 = rp[0];
		int m1 = rp[1];
		int m2 = rp[2];
		int m3 = rp[3];
		int m4 = rp[4];
		int m5 = rp[5];
		int m6 = rp[6];
		int m7 = rp[7];
		rp = T256_1[b1];
		m0 ^= rp[0];
		m1 ^= rp[1];
		m2 ^= rp[2];
		m3 ^= rp[3];
		m4 ^= rp[4];
		m5 ^= rp[5];
		m6 ^= rp[6];
		m7 ^= rp[7];
		rp = T256_2[b2];
		m0 ^= rp[0];
		m1 ^= rp[1];
		m2 ^= rp[2];
		m3 ^= rp[3];
		m4 ^= rp[4];
		m5 ^= rp[5];
		m6 ^= rp[6];
		m7 ^= rp[7];
		rp = T256_3[b3];
		m0 ^= rp[0];
		m1 ^= rp[1];
		m2 ^= rp[2];
		m3 ^= rp[3];
		m4 ^= rp[4];
		m5 ^= rp[5];
		m6 ^= rp[6];
		m7 ^= rp[7];

		int c0 = h[0];
		int c1 = h[1];
		int c2 = h[2];
		int c3 = h[3];
		int c4 = h[4];
		int c5 = h[5];
		int c6 = h[6];
		int c7 = h[7];
		int t;

		m0 ^= ALPHA_N[0x00];
		m1 ^= ALPHA_N[0x01] ^ 0;
		c0 ^= ALPHA_N[0x02];
		c1 ^= ALPHA_N[0x03];
		c2 ^= ALPHA_N[0x08];
		c3 ^= ALPHA_N[0x09];
		m2 ^= ALPHA_N[0x0A];
		m3 ^= ALPHA_N[0x0B];
		m4 ^= ALPHA_N[0x10];
		m5 ^= ALPHA_N[0x11];
		c4 ^= ALPHA_N[0x12];
		c5 ^= ALPHA_N[0x13];
		c6 ^= ALPHA_N[0x18];
		c7 ^= ALPHA_N[0x19];
		m6 ^= ALPHA_N[0x1A];
		m7 ^= ALPHA_N[0x1B];
		t = m0;
		m0 &= m4;
		m0 ^= c6;
		m4 ^= c2;
		m4 ^= m0;
		c6 |= t;
		c6 ^= c2;
		t ^= m4;
		c2 = c6;
		c6 |= t;
		c6 ^= m0;
		m0 &= c2;
		t ^= m0;
		c2 ^= c6;
		c2 ^= t;
		m0 = m4;
		m4 = c2;
		c2 = c6;
		c6 = ~t;
		t = m1;
		m1 &= m5;
		m1 ^= c7;
		m5 ^= c3;
		m5 ^= m1;
		c7 |= t;
		c7 ^= c3;
		t ^= m5;
		c3 = c7;
		c7 |= t;
		c7 ^= m1;
		m1 &= c3;
		t ^= m1;
		c3 ^= c7;
		c3 ^= t;
		m1 = m5;
		m5 = c3;
		c3 = c7;
		c7 = ~t;
		t = c0;
		c0 &= c4;
		c0 ^= m6;
		c4 ^= m2;
		c4 ^= c0;
		m6 |= t;
		m6 ^= m2;
		t ^= c4;
		m2 = m6;
		m6 |= t;
		m6 ^= c0;
		c0 &= m2;
		t ^= c0;
		m2 ^= m6;
		m2 ^= t;
		c0 = c4;
		c4 = m2;
		m2 = m6;
		m6 = ~t;
		t = c1;
		c1 &= c5;
		c1 ^= m7;
		c5 ^= m3;
		c5 ^= c1;
		m7 |= t;
		m7 ^= m3;
		t ^= c5;
		m3 = m7;
		m7 |= t;
		m7 ^= c1;
		c1 &= m3;
		t ^= c1;
		m3 ^= m7;
		m3 ^= t;
		c1 = c5;
		c5 = m3;
		m3 = m7;
		m7 = ~t;
		m0 = (m0 << 13) | (m0 >>> (32 - 13));
		c4 = (c4 << 3) | (c4 >>> (32 - 3));
		c3 ^= m0 ^ c4;
		m7 ^= c4 ^ (m0 << 3);
		c3 = (c3 << 1) | (c3 >>> (32 - 1));
		m7 = (m7 << 7) | (m7 >>> (32 - 7));
		m0 ^= c3 ^ m7;
		c4 ^= m7 ^ (c3 << 7);
		m0 = (m0 << 5) | (m0 >>> (32 - 5));
		c4 = (c4 << 22) | (c4 >>> (32 - 22));
		m1 = (m1 << 13) | (m1 >>> (32 - 13));
		c5 = (c5 << 3) | (c5 >>> (32 - 3));
		m2 ^= m1 ^ c5;
		c6 ^= c5 ^ (m1 << 3);
		m2 = (m2 << 1) | (m2 >>> (32 - 1));
		c6 = (c6 << 7) | (c6 >>> (32 - 7));
		m1 ^= m2 ^ c6;
		c5 ^= c6 ^ (m2 << 7);
		m1 = (m1 << 5) | (m1 >>> (32 - 5));
		c5 = (c5 << 22) | (c5 >>> (32 - 22));
		c0 = (c0 << 13) | (c0 >>> (32 - 13));
		m4 = (m4 << 3) | (m4 >>> (32 - 3));
		m3 ^= c0 ^ m4;
		c7 ^= m4 ^ (c0 << 3);
		m3 = (m3 << 1) | (m3 >>> (32 - 1));
		c7 = (c7 << 7) | (c7 >>> (32 - 7));
		c0 ^= m3 ^ c7;
		m4 ^= c7 ^ (m3 << 7);
		c0 = (c0 << 5) | (c0 >>> (32 - 5));
		m4 = (m4 << 22) | (m4 >>> (32 - 22));
		c1 = (c1 << 13) | (c1 >>> (32 - 13));
		m5 = (m5 << 3) | (m5 >>> (32 - 3));
		c2 ^= c1 ^ m5;
		m6 ^= m5 ^ (c1 << 3);
		c2 = (c2 << 1) | (c2 >>> (32 - 1));
		m6 = (m6 << 7) | (m6 >>> (32 - 7));
		c1 ^= c2 ^ m6;
		m5 ^= m6 ^ (c2 << 7);
		c1 = (c1 << 5) | (c1 >>> (32 - 5));
		m5 = (m5 << 22) | (m5 >>> (32 - 22));
		m0 ^= ALPHA_N[0x00];
		m1 ^= ALPHA_N[0x01] ^ 1;
		c0 ^= ALPHA_N[0x02];
		c1 ^= ALPHA_N[0x03];
		c2 ^= ALPHA_N[0x08];
		c3 ^= ALPHA_N[0x09];
		m2 ^= ALPHA_N[0x0A];
		m3 ^= ALPHA_N[0x0B];
		m4 ^= ALPHA_N[0x10];
		m5 ^= ALPHA_N[0x11];
		c4 ^= ALPHA_N[0x12];
		c5 ^= ALPHA_N[0x13];
		c6 ^= ALPHA_N[0x18];
		c7 ^= ALPHA_N[0x19];
		m6 ^= ALPHA_N[0x1A];
		m7 ^= ALPHA_N[0x1B];
		t = m0;
		m0 &= m4;
		m0 ^= c6;
		m4 ^= c2;
		m4 ^= m0;
		c6 |= t;
		c6 ^= c2;
		t ^= m4;
		c2 = c6;
		c6 |= t;
		c6 ^= m0;
		m0 &= c2;
		t ^= m0;
		c2 ^= c6;
		c2 ^= t;
		m0 = m4;
		m4 = c2;
		c2 = c6;
		c6 = ~t;
		t = m1;
		m1 &= m5;
		m1 ^= c7;
		m5 ^= c3;
		m5 ^= m1;
		c7 |= t;
		c7 ^= c3;
		t ^= m5;
		c3 = c7;
		c7 |= t;
		c7 ^= m1;
		m1 &= c3;
		t ^= m1;
		c3 ^= c7;
		c3 ^= t;
		m1 = m5;
		m5 = c3;
		c3 = c7;
		c7 = ~t;
		t = c0;
		c0 &= c4;
		c0 ^= m6;
		c4 ^= m2;
		c4 ^= c0;
		m6 |= t;
		m6 ^= m2;
		t ^= c4;
		m2 = m6;
		m6 |= t;
		m6 ^= c0;
		c0 &= m2;
		t ^= c0;
		m2 ^= m6;
		m2 ^= t;
		c0 = c4;
		c4 = m2;
		m2 = m6;
		m6 = ~t;
		t = c1;
		c1 &= c5;
		c1 ^= m7;
		c5 ^= m3;
		c5 ^= c1;
		m7 |= t;
		m7 ^= m3;
		t ^= c5;
		m3 = m7;
		m7 |= t;
		m7 ^= c1;
		c1 &= m3;
		t ^= c1;
		m3 ^= m7;
		m3 ^= t;
		c1 = c5;
		c5 = m3;
		m3 = m7;
		m7 = ~t;
		m0 = (m0 << 13) | (m0 >>> (32 - 13));
		c4 = (c4 << 3) | (c4 >>> (32 - 3));
		c3 ^= m0 ^ c4;
		m7 ^= c4 ^ (m0 << 3);
		c3 = (c3 << 1) | (c3 >>> (32 - 1));
		m7 = (m7 << 7) | (m7 >>> (32 - 7));
		m0 ^= c3 ^ m7;
		c4 ^= m7 ^ (c3 << 7);
		m0 = (m0 << 5) | (m0 >>> (32 - 5));
		c4 = (c4 << 22) | (c4 >>> (32 - 22));
		m1 = (m1 << 13) | (m1 >>> (32 - 13));
		c5 = (c5 << 3) | (c5 >>> (32 - 3));
		m2 ^= m1 ^ c5;
		c6 ^= c5 ^ (m1 << 3);
		m2 = (m2 << 1) | (m2 >>> (32 - 1));
		c6 = (c6 << 7) | (c6 >>> (32 - 7));
		m1 ^= m2 ^ c6;
		c5 ^= c6 ^ (m2 << 7);
		m1 = (m1 << 5) | (m1 >>> (32 - 5));
		c5 = (c5 << 22) | (c5 >>> (32 - 22));
		c0 = (c0 << 13) | (c0 >>> (32 - 13));
		m4 = (m4 << 3) | (m4 >>> (32 - 3));
		m3 ^= c0 ^ m4;
		c7 ^= m4 ^ (c0 << 3);
		m3 = (m3 << 1) | (m3 >>> (32 - 1));
		c7 = (c7 << 7) | (c7 >>> (32 - 7));
		c0 ^= m3 ^ c7;
		m4 ^= c7 ^ (m3 << 7);
		c0 = (c0 << 5) | (c0 >>> (32 - 5));
		m4 = (m4 << 22) | (m4 >>> (32 - 22));
		c1 = (c1 << 13) | (c1 >>> (32 - 13));
		m5 = (m5 << 3) | (m5 >>> (32 - 3));
		c2 ^= c1 ^ m5;
		m6 ^= m5 ^ (c1 << 3);
		c2 = (c2 << 1) | (c2 >>> (32 - 1));
		m6 = (m6 << 7) | (m6 >>> (32 - 7));
		c1 ^= c2 ^ m6;
		m5 ^= m6 ^ (c2 << 7);
		c1 = (c1 << 5) | (c1 >>> (32 - 5));
		m5 = (m5 << 22) | (m5 >>> (32 - 22));
		m0 ^= ALPHA_N[0x00];
		m1 ^= ALPHA_N[0x01] ^ 2;
		c0 ^= ALPHA_N[0x02];
		c1 ^= ALPHA_N[0x03];
		c2 ^= ALPHA_N[0x08];
		c3 ^= ALPHA_N[0x09];
		m2 ^= ALPHA_N[0x0A];
		m3 ^= ALPHA_N[0x0B];
		m4 ^= ALPHA_N[0x10];
		m5 ^= ALPHA_N[0x11];
		c4 ^= ALPHA_N[0x12];
		c5 ^= ALPHA_N[0x13];
		c6 ^= ALPHA_N[0x18];
		c7 ^= ALPHA_N[0x19];
		m6 ^= ALPHA_N[0x1A];
		m7 ^= ALPHA_N[0x1B];
		t = m0;
		m0 &= m4;
		m0 ^= c6;
		m4 ^= c2;
		m4 ^= m0;
		c6 |= t;
		c6 ^= c2;
		t ^= m4;
		c2 = c6;
		c6 |= t;
		c6 ^= m0;
		m0 &= c2;
		t ^= m0;
		c2 ^= c6;
		c2 ^= t;
		m0 = m4;
		m4 = c2;
		c2 = c6;
		c6 = ~t;
		t = m1;
		m1 &= m5;
		m1 ^= c7;
		m5 ^= c3;
		m5 ^= m1;
		c7 |= t;
		c7 ^= c3;
		t ^= m5;
		c3 = c7;
		c7 |= t;
		c7 ^= m1;
		m1 &= c3;
		t ^= m1;
		c3 ^= c7;
		c3 ^= t;
		m1 = m5;
		m5 = c3;
		c3 = c7;
		c7 = ~t;
		t = c0;
		c0 &= c4;
		c0 ^= m6;
		c4 ^= m2;
		c4 ^= c0;
		m6 |= t;
		m6 ^= m2;
		t ^= c4;
		m2 = m6;
		m6 |= t;
		m6 ^= c0;
		c0 &= m2;
		t ^= c0;
		m2 ^= m6;
		m2 ^= t;
		c0 = c4;
		c4 = m2;
		m2 = m6;
		m6 = ~t;
		t = c1;
		c1 &= c5;
		c1 ^= m7;
		c5 ^= m3;
		c5 ^= c1;
		m7 |= t;
		m7 ^= m3;
		t ^= c5;
		m3 = m7;
		m7 |= t;
		m7 ^= c1;
		c1 &= m3;
		t ^= c1;
		m3 ^= m7;
		m3 ^= t;
		c1 = c5;
		c5 = m3;
		m3 = m7;
		m7 = ~t;
		m0 = (m0 << 13) | (m0 >>> (32 - 13));
		c4 = (c4 << 3) | (c4 >>> (32 - 3));
		c3 ^= m0 ^ c4;
		m7 ^= c4 ^ (m0 << 3);
		c3 = (c3 << 1) | (c3 >>> (32 - 1));
		m7 = (m7 << 7) | (m7 >>> (32 - 7));
		m0 ^= c3 ^ m7;
		c4 ^= m7 ^ (c3 << 7);
		m0 = (m0 << 5) | (m0 >>> (32 - 5));
		c4 = (c4 << 22) | (c4 >>> (32 - 22));
		m1 = (m1 << 13) | (m1 >>> (32 - 13));
		c5 = (c5 << 3) | (c5 >>> (32 - 3));
		m2 ^= m1 ^ c5;
		c6 ^= c5 ^ (m1 << 3);
		m2 = (m2 << 1) | (m2 >>> (32 - 1));
		c6 = (c6 << 7) | (c6 >>> (32 - 7));
		m1 ^= m2 ^ c6;
		c5 ^= c6 ^ (m2 << 7);
		m1 = (m1 << 5) | (m1 >>> (32 - 5));
		c5 = (c5 << 22) | (c5 >>> (32 - 22));
		c0 = (c0 << 13) | (c0 >>> (32 - 13));
		m4 = (m4 << 3) | (m4 >>> (32 - 3));
		m3 ^= c0 ^ m4;
		c7 ^= m4 ^ (c0 << 3);
		m3 = (m3 << 1) | (m3 >>> (32 - 1));
		c7 = (c7 << 7) | (c7 >>> (32 - 7));
		c0 ^= m3 ^ c7;
		m4 ^= c7 ^ (m3 << 7);
		c0 = (c0 << 5) | (c0 >>> (32 - 5));
		m4 = (m4 << 22) | (m4 >>> (32 - 22));
		c1 = (c1 << 13) | (c1 >>> (32 - 13));
		m5 = (m5 << 3) | (m5 >>> (32 - 3));
		c2 ^= c1 ^ m5;
		m6 ^= m5 ^ (c1 << 3);
		c2 = (c2 << 1) | (c2 >>> (32 - 1));
		m6 = (m6 << 7) | (m6 >>> (32 - 7));
		c1 ^= c2 ^ m6;
		m5 ^= m6 ^ (c2 << 7);
		c1 = (c1 << 5) | (c1 >>> (32 - 5));
		m5 = (m5 << 22) | (m5 >>> (32 - 22));

		h[7] ^= c5;
		h[6] ^= c4;
		h[5] ^= m5;
		h[4] ^= m4;
		h[3] ^= c1;
		h[2] ^= c0;
		h[1] ^= m1;
		h[0] ^= m0;
	}

	private void processFinal(int b0, int b1, int b2, int b3)
	{
		int[] rp = T256_0[b0];
		int m0 = rp[0];
		int m1 = rp[1];
		int m2 = rp[2];
		int m3 = rp[3];
		int m4 = rp[4];
		int m5 = rp[5];
		int m6 = rp[6];
		int m7 = rp[7];
		rp = T256_1[b1];
		m0 ^= rp[0];
		m1 ^= rp[1];
		m2 ^= rp[2];
		m3 ^= rp[3];
		m4 ^= rp[4];
		m5 ^= rp[5];
		m6 ^= rp[6];
		m7 ^= rp[7];
		rp = T256_2[b2];
		m0 ^= rp[0];
		m1 ^= rp[1];
		m2 ^= rp[2];
		m3 ^= rp[3];
		m4 ^= rp[4];
		m5 ^= rp[5];
		m6 ^= rp[6];
		m7 ^= rp[7];
		rp = T256_3[b3];
		m0 ^= rp[0];
		m1 ^= rp[1];
		m2 ^= rp[2];
		m3 ^= rp[3];
		m4 ^= rp[4];
		m5 ^= rp[5];
		m6 ^= rp[6];
		m7 ^= rp[7];

		int c0 = h[0];
		int c1 = h[1];
		int c2 = h[2];
		int c3 = h[3];
		int c4 = h[4];
		int c5 = h[5];
		int c6 = h[6];
		int c7 = h[7];
		int t;

		for (int r = 0; r < 6; r ++) {
			m0 ^= ALPHA_F[0x00];
			m1 ^= ALPHA_F[0x01] ^ r;
			c0 ^= ALPHA_F[0x02];
			c1 ^= ALPHA_F[0x03];
			c2 ^= ALPHA_F[0x08];
			c3 ^= ALPHA_F[0x09];
			m2 ^= ALPHA_F[0x0A];
			m3 ^= ALPHA_F[0x0B];
			m4 ^= ALPHA_F[0x10];
			m5 ^= ALPHA_F[0x11];
			c4 ^= ALPHA_F[0x12];
			c5 ^= ALPHA_F[0x13];
			c6 ^= ALPHA_F[0x18];
			c7 ^= ALPHA_F[0x19];
			m6 ^= ALPHA_F[0x1A];
			m7 ^= ALPHA_F[0x1B];
			t = m0;
			m0 &= m4;
			m0 ^= c6;
			m4 ^= c2;
			m4 ^= m0;
			c6 |= t;
			c6 ^= c2;
			t ^= m4;
			c2 = c6;
			c6 |= t;
			c6 ^= m0;
			m0 &= c2;
			t ^= m0;
			c2 ^= c6;
			c2 ^= t;
			m0 = m4;
			m4 = c2;
			c2 = c6;
			c6 = ~t;
			t = m1;
			m1 &= m5;
			m1 ^= c7;
			m5 ^= c3;
			m5 ^= m1;
			c7 |= t;
			c7 ^= c3;
			t ^= m5;
			c3 = c7;
			c7 |= t;
			c7 ^= m1;
			m1 &= c3;
			t ^= m1;
			c3 ^= c7;
			c3 ^= t;
			m1 = m5;
			m5 = c3;
			c3 = c7;
			c7 = ~t;
			t = c0;
			c0 &= c4;
			c0 ^= m6;
			c4 ^= m2;
			c4 ^= c0;
			m6 |= t;
			m6 ^= m2;
			t ^= c4;
			m2 = m6;
			m6 |= t;
			m6 ^= c0;
			c0 &= m2;
			t ^= c0;
			m2 ^= m6;
			m2 ^= t;
			c0 = c4;
			c4 = m2;
			m2 = m6;
			m6 = ~t;
			t = c1;
			c1 &= c5;
			c1 ^= m7;
			c5 ^= m3;
			c5 ^= c1;
			m7 |= t;
			m7 ^= m3;
			t ^= c5;
			m3 = m7;
			m7 |= t;
			m7 ^= c1;
			c1 &= m3;
			t ^= c1;
			m3 ^= m7;
			m3 ^= t;
			c1 = c5;
			c5 = m3;
			m3 = m7;
			m7 = ~t;
			m0 = (m0 << 13) | (m0 >>> (32 - 13));
			c4 = (c4 << 3) | (c4 >>> (32 - 3));
			c3 ^= m0 ^ c4;
			m7 ^= c4 ^ (m0 << 3);
			c3 = (c3 << 1) | (c3 >>> (32 - 1));
			m7 = (m7 << 7) | (m7 >>> (32 - 7));
			m0 ^= c3 ^ m7;
			c4 ^= m7 ^ (c3 << 7);
			m0 = (m0 << 5) | (m0 >>> (32 - 5));
			c4 = (c4 << 22) | (c4 >>> (32 - 22));
			m1 = (m1 << 13) | (m1 >>> (32 - 13));
			c5 = (c5 << 3) | (c5 >>> (32 - 3));
			m2 ^= m1 ^ c5;
			c6 ^= c5 ^ (m1 << 3);
			m2 = (m2 << 1) | (m2 >>> (32 - 1));
			c6 = (c6 << 7) | (c6 >>> (32 - 7));
			m1 ^= m2 ^ c6;
			c5 ^= c6 ^ (m2 << 7);
			m1 = (m1 << 5) | (m1 >>> (32 - 5));
			c5 = (c5 << 22) | (c5 >>> (32 - 22));
			c0 = (c0 << 13) | (c0 >>> (32 - 13));
			m4 = (m4 << 3) | (m4 >>> (32 - 3));
			m3 ^= c0 ^ m4;
			c7 ^= m4 ^ (c0 << 3);
			m3 = (m3 << 1) | (m3 >>> (32 - 1));
			c7 = (c7 << 7) | (c7 >>> (32 - 7));
			c0 ^= m3 ^ c7;
			m4 ^= c7 ^ (m3 << 7);
			c0 = (c0 << 5) | (c0 >>> (32 - 5));
			m4 = (m4 << 22) | (m4 >>> (32 - 22));
			c1 = (c1 << 13) | (c1 >>> (32 - 13));
			m5 = (m5 << 3) | (m5 >>> (32 - 3));
			c2 ^= c1 ^ m5;
			m6 ^= m5 ^ (c1 << 3);
			c2 = (c2 << 1) | (c2 >>> (32 - 1));
			m6 = (m6 << 7) | (m6 >>> (32 - 7));
			c1 ^= c2 ^ m6;
			m5 ^= m6 ^ (c2 << 7);
			c1 = (c1 << 5) | (c1 >>> (32 - 5));
			m5 = (m5 << 22) | (m5 >>> (32 - 22));
		}

		h[7] ^= c5;
		h[6] ^= c4;
		h[5] ^= m5;
		h[4] ^= m4;
		h[3] ^= c1;
		h[2] ^= c0;
		h[1] ^= m1;
		h[0] ^= m0;
	}

	/** @see Digest */
	public String toString()
	{
		return "Hamsi-" + (getDigestLength() << 3);
	}
}
