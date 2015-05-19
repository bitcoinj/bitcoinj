// $Id: HamsiBigCore.java 239 2010-06-21 14:58:08Z tp $

package fr.cryptohash;

/**
 * This class implements Hamsi-384 and Hamsi-512.
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

abstract class HamsiBigCore implements Digest {

	private int[] h;
	private long bitCount;
	private long partial;
	private int partialLen;

	/**
	 * Create the object.
	 */
	HamsiBigCore()
	{
		h = new int[16];
		reset();
	}

	/** @see Digest */
	public void update(byte in)
	{
		bitCount += 8;
		partial = (partial << 8) | (in & 0xFF);
		partialLen ++;
		if (partialLen == 8) {
			process((int)(partial >>> 56) & 0xFF,
				(int)(partial >>> 48) & 0xFF,
				(int)(partial >>> 40) & 0xFF,
				(int)(partial >>> 32) & 0xFF,
				((int)partial >>> 24) & 0xFF,
				((int)partial >>> 16) & 0xFF,
				((int)partial >>> 8) & 0xFF,
				(int)partial & 0xFF);
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
			while (partialLen < 8 && len > 0) {
				partial = (partial << 8)
					| (inbuf[off ++] & 0xFF);
				partialLen ++;
				len --;
			}
			if (partialLen < 8)
				return;
			process((int)(partial >>> 56) & 0xFF,
				(int)(partial >>> 48) & 0xFF,
				(int)(partial >>> 40) & 0xFF,
				(int)(partial >>> 32) & 0xFF,
				((int)partial >>> 24) & 0xFF,
				((int)partial >>> 16) & 0xFF,
				((int)partial >>> 8) & 0xFF,
				(int)partial & 0xFF);
			partialLen = 0;
		}
		while (len >= 8) {
			process(inbuf[off + 0] & 0xFF,
				inbuf[off + 1] & 0xFF,
				inbuf[off + 2] & 0xFF,
				inbuf[off + 3] & 0xFF,
				inbuf[off + 4] & 0xFF,
				inbuf[off + 5] & 0xFF,
				inbuf[off + 6] & 0xFF,
				inbuf[off + 7] & 0xFF);
			off += 8;
			len -= 8;
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

	private static final int[] HOFF384 = {
		0, 1, 3, 4, 5, 6, 8, 9, 10, 12, 13, 15
	};

	private static final int[] HOFF512 = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
	};

	/** @see Digest */
	public int digest(byte[] outbuf, int off, int len)
	{
		long bitCount = this.bitCount;
		update((byte)0x80);
		while (partialLen != 0)
			update((byte)0x00);
		processFinal((int)(bitCount >>> 56) & 0xFF,
			(int)(bitCount >>> 48) & 0xFF,
			(int)(bitCount >>> 40) & 0xFF,
			(int)(bitCount >>> 32) & 0xFF,
			((int)bitCount >>> 24) & 0xFF,
			((int)bitCount >>> 16) & 0xFF,
			((int)bitCount >>> 8) & 0xFF,
			(int)bitCount & 0xFF);
		int n = getDigestLength();
		if (len > n)
			len = n;
		int ch = 0;
		int[] hoff = (n == 48) ? HOFF384 : HOFF512;
		for (int i = 0, j = 0; i < len; i ++) {
			if ((i & 3) == 0)
				ch = h[hoff[j ++]];
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
		HamsiBigCore d = dup();
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
	abstract HamsiBigCore dup();

	private static final int[][] Tsrc = {
		{ 0x466d0c00, 0x08620000, 0xdd5d0000, 0xbadd0000,
		  0x6a927942, 0x441f2b93, 0x218ace6f, 0xbf2c0be2,
		  0x6f299000, 0x6c850000, 0x2f160000, 0x782e0000,
		  0x644c37cd, 0x12dd1cd6, 0xd26a8c36, 0x32219526 },
		{ 0x29449c00, 0x64e70000, 0xf24b0000, 0xc2f30000,
		  0x0ede4e8f, 0x56c23745, 0xf3e04259, 0x8d0d9ec4,
		  0x466d0c00, 0x08620000, 0xdd5d0000, 0xbadd0000,
		  0x6a927942, 0x441f2b93, 0x218ace6f, 0xbf2c0be2 },
		{ 0x9cbb1800, 0xb0d30000, 0x92510000, 0xed930000,
		  0x593a4345, 0xe114d5f4, 0x430633da, 0x78cace29,
		  0xc8934400, 0x5a3e0000, 0x57870000, 0x4c560000,
		  0xea982435, 0x75b11115, 0x28b67247, 0x2dd1f9ab },
		{ 0x54285c00, 0xeaed0000, 0xc5d60000, 0xa1c50000,
		  0xb3a26770, 0x94a5c4e1, 0x6bb0419d, 0x551b3782,
		  0x9cbb1800, 0xb0d30000, 0x92510000, 0xed930000,
		  0x593a4345, 0xe114d5f4, 0x430633da, 0x78cace29 },
		{ 0x23671400, 0xc8b90000, 0xf4c70000, 0xfb750000,
		  0x73cd2465, 0xf8a6a549, 0x02c40a3f, 0xdc24e61f,
		  0x373d2800, 0x71500000, 0x95e00000, 0x0a140000,
		  0xbdac1909, 0x48ef9831, 0x456d6d1f, 0x3daac2da },
		{ 0x145a3c00, 0xb9e90000, 0x61270000, 0xf1610000,
		  0xce613d6c, 0xb0493d78, 0x47a96720, 0xe18e24c5,
		  0x23671400, 0xc8b90000, 0xf4c70000, 0xfb750000,
		  0x73cd2465, 0xf8a6a549, 0x02c40a3f, 0xdc24e61f },
		{ 0xc96b0030, 0xe7250000, 0x2f840000, 0x264f0000,
		  0x08695bf9, 0x6dfcf137, 0x509f6984, 0x9e69af68,
		  0x26600240, 0xddd80000, 0x722a0000, 0x4f060000,
		  0x936667ff, 0x29f944ce, 0x368b63d5, 0x0c26f262 },
		{ 0xef0b0270, 0x3afd0000, 0x5dae0000, 0x69490000,
		  0x9b0f3c06, 0x4405b5f9, 0x66140a51, 0x924f5d0a,
		  0xc96b0030, 0xe7250000, 0x2f840000, 0x264f0000,
		  0x08695bf9, 0x6dfcf137, 0x509f6984, 0x9e69af68 },
		{ 0xb4370060, 0x0c4c0000, 0x56c20000, 0x5cae0000,
		  0x94541f3f, 0x3b3ef825, 0x1b365f3d, 0xf3d45758,
		  0x5cb00110, 0x913e0000, 0x44190000, 0x888c0000,
		  0x66dc7418, 0x921f1d66, 0x55ceea25, 0x925c44e9 },
		{ 0xe8870170, 0x9d720000, 0x12db0000, 0xd4220000,
		  0xf2886b27, 0xa921e543, 0x4ef8b518, 0x618813b1,
		  0xb4370060, 0x0c4c0000, 0x56c20000, 0x5cae0000,
		  0x94541f3f, 0x3b3ef825, 0x1b365f3d, 0xf3d45758 },
		{ 0xf46c0050, 0x96180000, 0x14a50000, 0x031f0000,
		  0x42947eb8, 0x66bf7e19, 0x9ca470d2, 0x8a341574,
		  0x832800a0, 0x67420000, 0xe1170000, 0x370b0000,
		  0xcba30034, 0x3c34923c, 0x9767bdcc, 0x450360bf },
		{ 0x774400f0, 0xf15a0000, 0xf5b20000, 0x34140000,
		  0x89377e8c, 0x5a8bec25, 0x0bc3cd1e, 0xcf3775cb,
		  0xf46c0050, 0x96180000, 0x14a50000, 0x031f0000,
		  0x42947eb8, 0x66bf7e19, 0x9ca470d2, 0x8a341574 },
		{ 0xd46a0000, 0x8dc8c000, 0xa5af0000, 0x4a290000,
		  0xfc4e427a, 0xc9b4866c, 0x98369604, 0xf746c320,
		  0x231f0009, 0x42f40000, 0x66790000, 0x4ebb0000,
		  0xfedb5bd3, 0x315cb0d6, 0xe2b1674a, 0x69505b3a },
		{ 0xf7750009, 0xcf3cc000, 0xc3d60000, 0x04920000,
		  0x029519a9, 0xf8e836ba, 0x7a87f14e, 0x9e16981a,
		  0xd46a0000, 0x8dc8c000, 0xa5af0000, 0x4a290000,
		  0xfc4e427a, 0xc9b4866c, 0x98369604, 0xf746c320 },
		{ 0xa67f0001, 0x71378000, 0x19fc0000, 0x96db0000,
		  0x3a8b6dfd, 0xebcaaef3, 0x2c6d478f, 0xac8e6c88,
		  0x50ff0004, 0x45744000, 0x3dfb0000, 0x19e60000,
		  0x1bbc5606, 0xe1727b5d, 0xe1a8cc96, 0x7b1bd6b9 },
		{ 0xf6800005, 0x3443c000, 0x24070000, 0x8f3d0000,
		  0x21373bfb, 0x0ab8d5ae, 0xcdc58b19, 0xd795ba31,
		  0xa67f0001, 0x71378000, 0x19fc0000, 0x96db0000,
		  0x3a8b6dfd, 0xebcaaef3, 0x2c6d478f, 0xac8e6c88 },
		{ 0xeecf0001, 0x6f564000, 0xf33e0000, 0xa79e0000,
		  0xbdb57219, 0xb711ebc5, 0x4a3b40ba, 0xfeabf254,
		  0x9b060002, 0x61468000, 0x221e0000, 0x1d740000,
		  0x36715d27, 0x30495c92, 0xf11336a7, 0xfe1cdc7f },
		{ 0x75c90003, 0x0e10c000, 0xd1200000, 0xbaea0000,
		  0x8bc42f3e, 0x8758b757, 0xbb28761d, 0x00b72e2b,
		  0xeecf0001, 0x6f564000, 0xf33e0000, 0xa79e0000,
		  0xbdb57219, 0xb711ebc5, 0x4a3b40ba, 0xfeabf254 },
		{ 0xd1660000, 0x1bbc0300, 0x9eec0000, 0xf6940000,
		  0x03024527, 0xcf70fcf2, 0xb4431b17, 0x857f3c2b,
		  0xa4c20000, 0xd9372400, 0x0a480000, 0x66610000,
		  0xf87a12c7, 0x86bef75c, 0xa324df94, 0x2ba05a55 },
		{ 0x75a40000, 0xc28b2700, 0x94a40000, 0x90f50000,
		  0xfb7857e0, 0x49ce0bae, 0x1767c483, 0xaedf667e,
		  0xd1660000, 0x1bbc0300, 0x9eec0000, 0xf6940000,
		  0x03024527, 0xcf70fcf2, 0xb4431b17, 0x857f3c2b },
		{ 0xb83d0000, 0x16710600, 0x379a0000, 0xf5b10000,
		  0x228161ac, 0xae48f145, 0x66241616, 0xc5c1eb3e,
		  0xfd250000, 0xb3c41100, 0xcef00000, 0xcef90000,
		  0x3c4d7580, 0x8d5b6493, 0x7098b0a6, 0x1af21fe1 },
		{ 0x45180000, 0xa5b51700, 0xf96a0000, 0x3b480000,
		  0x1ecc142c, 0x231395d6, 0x16bca6b0, 0xdf33f4df,
		  0xb83d0000, 0x16710600, 0x379a0000, 0xf5b10000,
		  0x228161ac, 0xae48f145, 0x66241616, 0xc5c1eb3e },
		{ 0xfe220000, 0xa7580500, 0x25d10000, 0xf7600000,
		  0x893178da, 0x1fd4f860, 0x4ed0a315, 0xa123ff9f,
		  0xf2500000, 0xeebd0a00, 0x67a80000, 0xab8a0000,
		  0xba9b48c0, 0x0a56dd74, 0xdb73e86e, 0x1568ff0f },
		{ 0x0c720000, 0x49e50f00, 0x42790000, 0x5cea0000,
		  0x33aa301a, 0x15822514, 0x95a34b7b, 0xb44b0090,
		  0xfe220000, 0xa7580500, 0x25d10000, 0xf7600000,
		  0x893178da, 0x1fd4f860, 0x4ed0a315, 0xa123ff9f },
		{ 0xc6730000, 0xaf8d000c, 0xa4c10000, 0x218d0000,
		  0x23111587, 0x7913512f, 0x1d28ac88, 0x378dd173,
		  0xaf220000, 0x7b6c0090, 0x67e20000, 0x8da20000,
		  0xc7841e29, 0xb7b744f3, 0x9ac484f4, 0x8b6c72bd },
		{ 0x69510000, 0xd4e1009c, 0xc3230000, 0xac2f0000,
		  0xe4950bae, 0xcea415dc, 0x87ec287c, 0xbce1a3ce,
		  0xc6730000, 0xaf8d000c, 0xa4c10000, 0x218d0000,
		  0x23111587, 0x7913512f, 0x1d28ac88, 0x378dd173 },
		{ 0xbc8d0000, 0xfc3b0018, 0x19830000, 0xd10b0000,
		  0xae1878c4, 0x42a69856, 0x0012da37, 0x2c3b504e,
		  0xe8dd0000, 0xfa4a0044, 0x3c2d0000, 0xbb150000,
		  0x80bd361b, 0x24e81d44, 0xbfa8c2f4, 0x524a0d59 },
		{ 0x54500000, 0x0671005c, 0x25ae0000, 0x6a1e0000,
		  0x2ea54edf, 0x664e8512, 0xbfba18c3, 0x7e715d17,
		  0xbc8d0000, 0xfc3b0018, 0x19830000, 0xd10b0000,
		  0xae1878c4, 0x42a69856, 0x0012da37, 0x2c3b504e },
		{ 0xe3430000, 0x3a4e0014, 0xf2c60000, 0xaa4e0000,
		  0xdb1e42a6, 0x256bbe15, 0x123db156, 0x3a4e99d7,
		  0xf75a0000, 0x19840028, 0xa2190000, 0xeef80000,
		  0xc0722516, 0x19981260, 0x73dba1e6, 0xe1844257 },
		{ 0x14190000, 0x23ca003c, 0x50df0000, 0x44b60000,
		  0x1b6c67b0, 0x3cf3ac75, 0x61e610b0, 0xdbcadb80,
		  0xe3430000, 0x3a4e0014, 0xf2c60000, 0xaa4e0000,
		  0xdb1e42a6, 0x256bbe15, 0x123db156, 0x3a4e99d7 },
		{ 0x30b70000, 0xe5d00000, 0xf4f46000, 0x42c40000,
		  0x63b83d6a, 0x78ba9460, 0x21afa1ea, 0xb0a51834,
		  0xb6ce0000, 0xdae90002, 0x156e8000, 0xda920000,
		  0xf6dd5a64, 0x36325c8a, 0xf272e8ae, 0xa6b8c28d },
		{ 0x86790000, 0x3f390002, 0xe19ae000, 0x98560000,
		  0x9565670e, 0x4e88c8ea, 0xd3dd4944, 0x161ddab9,
		  0x30b70000, 0xe5d00000, 0xf4f46000, 0x42c40000,
		  0x63b83d6a, 0x78ba9460, 0x21afa1ea, 0xb0a51834 },
		{ 0xdb250000, 0x09290000, 0x49aac000, 0x81e10000,
		  0xcafe6b59, 0x42793431, 0x43566b76, 0xe86cba2e,
		  0x75e60000, 0x95660001, 0x307b2000, 0xadf40000,
		  0x8f321eea, 0x24298307, 0xe8c49cf9, 0x4b7eec55 },
		{ 0xaec30000, 0x9c4f0001, 0x79d1e000, 0x2c150000,
		  0x45cc75b3, 0x6650b736, 0xab92f78f, 0xa312567b,
		  0xdb250000, 0x09290000, 0x49aac000, 0x81e10000,
		  0xcafe6b59, 0x42793431, 0x43566b76, 0xe86cba2e },
		{ 0x1e4e0000, 0xdecf0000, 0x6df80180, 0x77240000,
		  0xec47079e, 0xf4a0694e, 0xcda31812, 0x98aa496e,
		  0xb2060000, 0xc5690000, 0x28031200, 0x74670000,
		  0xb6c236f4, 0xeb1239f8, 0x33d1dfec, 0x094e3198 },
		{ 0xac480000, 0x1ba60000, 0x45fb1380, 0x03430000,
		  0x5a85316a, 0x1fb250b6, 0xfe72c7fe, 0x91e478f6,
		  0x1e4e0000, 0xdecf0000, 0x6df80180, 0x77240000,
		  0xec47079e, 0xf4a0694e, 0xcda31812, 0x98aa496e },
		{ 0x02af0000, 0xb7280000, 0xba1c0300, 0x56980000,
		  0xba8d45d3, 0x8048c667, 0xa95c149a, 0xf4f6ea7b,
		  0x7a8c0000, 0xa5d40000, 0x13260880, 0xc63d0000,
		  0xcbb36daa, 0xfea14f43, 0x59d0b4f8, 0x979961d0 },
		{ 0x78230000, 0x12fc0000, 0xa93a0b80, 0x90a50000,
		  0x713e2879, 0x7ee98924, 0xf08ca062, 0x636f8bab,
		  0x02af0000, 0xb7280000, 0xba1c0300, 0x56980000,
		  0xba8d45d3, 0x8048c667, 0xa95c149a, 0xf4f6ea7b },
		{ 0x819e0000, 0xec570000, 0x66320280, 0x95f30000,
		  0x5da92802, 0x48f43cbc, 0xe65aa22d, 0x8e67b7fa,
		  0x4d8a0000, 0x49340000, 0x3c8b0500, 0xaea30000,
		  0x16793bfd, 0xcf6f08a4, 0x8f19eaec, 0x443d3004 },
		{ 0xcc140000, 0xa5630000, 0x5ab90780, 0x3b500000,
		  0x4bd013ff, 0x879b3418, 0x694348c1, 0xca5a87fe,
		  0x819e0000, 0xec570000, 0x66320280, 0x95f30000,
		  0x5da92802, 0x48f43cbc, 0xe65aa22d, 0x8e67b7fa },
		{ 0x538d0000, 0xa9fc0000, 0x9ef70006, 0x56ff0000,
		  0x0ae4004e, 0x92c5cdf9, 0xa9444018, 0x7f975691,
		  0x01dd0000, 0x80a80000, 0xf4960048, 0xa6000000,
		  0x90d57ea2, 0xd7e68c37, 0x6612cffd, 0x2c94459e },
		{ 0x52500000, 0x29540000, 0x6a61004e, 0xf0ff0000,
		  0x9a317eec, 0x452341ce, 0xcf568fe5, 0x5303130f,
		  0x538d0000, 0xa9fc0000, 0x9ef70006, 0x56ff0000,
		  0x0ae4004e, 0x92c5cdf9, 0xa9444018, 0x7f975691 },
		{ 0x0bc20000, 0xdb630000, 0x7e88000c, 0x15860000,
		  0x91fd48f3, 0x7581bb43, 0xf460449e, 0xd8b61463,
		  0x835a0000, 0xc4f70000, 0x01470022, 0xeec80000,
		  0x60a54f69, 0x142f2a24, 0x5cf534f2, 0x3ea660f7 },
		{ 0x88980000, 0x1f940000, 0x7fcf002e, 0xfb4e0000,
		  0xf158079a, 0x61ae9167, 0xa895706c, 0xe6107494,
		  0x0bc20000, 0xdb630000, 0x7e88000c, 0x15860000,
		  0x91fd48f3, 0x7581bb43, 0xf460449e, 0xd8b61463 },
		{ 0x07ed0000, 0xb2500000, 0x8774000a, 0x970d0000,
		  0x437223ae, 0x48c76ea4, 0xf4786222, 0x9075b1ce,
		  0xa2d60000, 0xa6760000, 0xc9440014, 0xeba30000,
		  0xccec2e7b, 0x3018c499, 0x03490afa, 0x9b6ef888 },
		{ 0xa53b0000, 0x14260000, 0x4e30001e, 0x7cae0000,
		  0x8f9e0dd5, 0x78dfaa3d, 0xf73168d8, 0x0b1b4946,
		  0x07ed0000, 0xb2500000, 0x8774000a, 0x970d0000,
		  0x437223ae, 0x48c76ea4, 0xf4786222, 0x9075b1ce },
		{ 0x1d5a0000, 0x2b720000, 0x488d0000, 0xaf611800,
		  0x25cb2ec5, 0xc879bfd0, 0x81a20429, 0x1e7536a6,
		  0x45190000, 0xab0c0000, 0x30be0001, 0x690a2000,
		  0xc2fc7219, 0xb1d4800d, 0x2dd1fa46, 0x24314f17 },
		{ 0x58430000, 0x807e0000, 0x78330001, 0xc66b3800,
		  0xe7375cdc, 0x79ad3fdd, 0xac73fe6f, 0x3a4479b1,
		  0x1d5a0000, 0x2b720000, 0x488d0000, 0xaf611800,
		  0x25cb2ec5, 0xc879bfd0, 0x81a20429, 0x1e7536a6 },
		{ 0x92560000, 0x1eda0000, 0xea510000, 0xe8b13000,
		  0xa93556a5, 0xebfb6199, 0xb15c2254, 0x33c5244f,
		  0x8c3a0000, 0xda980000, 0x607f0000, 0x54078800,
		  0x85714513, 0x6006b243, 0xdb50399c, 0x8a58e6a4 },
		{ 0x1e6c0000, 0xc4420000, 0x8a2e0000, 0xbcb6b800,
		  0x2c4413b6, 0x8bfdd3da, 0x6a0c1bc8, 0xb99dc2eb,
		  0x92560000, 0x1eda0000, 0xea510000, 0xe8b13000,
		  0xa93556a5, 0xebfb6199, 0xb15c2254, 0x33c5244f },
		{ 0xbadd0000, 0x13ad0000, 0xb7e70000, 0xf7282800,
		  0xdf45144d, 0x361ac33a, 0xea5a8d14, 0x2a2c18f0,
		  0xb82f0000, 0xb12c0000, 0x30d80000, 0x14445000,
		  0xc15860a2, 0x3127e8ec, 0x2e98bf23, 0x551e3d6e },
		{ 0x02f20000, 0xa2810000, 0x873f0000, 0xe36c7800,
		  0x1e1d74ef, 0x073d2bd6, 0xc4c23237, 0x7f32259e,
		  0xbadd0000, 0x13ad0000, 0xb7e70000, 0xf7282800,
		  0xdf45144d, 0x361ac33a, 0xea5a8d14, 0x2a2c18f0 },
		{ 0xe3060000, 0xbdc10000, 0x87130000, 0xbff20060,
		  0x2eba0a1a, 0x8db53751, 0x73c5ab06, 0x5bd61539,
		  0x57370000, 0xcaf20000, 0x364e0000, 0xc0220480,
		  0x56186b22, 0x5ca3f40c, 0xa1937f8f, 0x15b961e7 },
		{ 0xb4310000, 0x77330000, 0xb15d0000, 0x7fd004e0,
		  0x78a26138, 0xd116c35d, 0xd256d489, 0x4e6f74de,
		  0xe3060000, 0xbdc10000, 0x87130000, 0xbff20060,
		  0x2eba0a1a, 0x8db53751, 0x73c5ab06, 0x5bd61539 },
		{ 0xf0c50000, 0x59230000, 0x45820000, 0xe18d00c0,
		  0x3b6d0631, 0xc2ed5699, 0xcbe0fe1c, 0x56a7b19f,
		  0x16ed0000, 0x15680000, 0xedd70000, 0x325d0220,
		  0xe30c3689, 0x5a4ae643, 0xe375f8a8, 0x81fdf908 },
		{ 0xe6280000, 0x4c4b0000, 0xa8550000, 0xd3d002e0,
		  0xd86130b8, 0x98a7b0da, 0x289506b4, 0xd75a4897,
		  0xf0c50000, 0x59230000, 0x45820000, 0xe18d00c0,
		  0x3b6d0631, 0xc2ed5699, 0xcbe0fe1c, 0x56a7b19f },
		{ 0x7b280000, 0x57420000, 0xa9e50000, 0x634300a0,
		  0x9edb442f, 0x6d9995bb, 0x27f83b03, 0xc7ff60f0,
		  0x95bb0000, 0x81450000, 0x3b240000, 0x48db0140,
		  0x0a8a6c53, 0x56f56eec, 0x62c91877, 0xe7e00a94 },
		{ 0xee930000, 0xd6070000, 0x92c10000, 0x2b9801e0,
		  0x9451287c, 0x3b6cfb57, 0x45312374, 0x201f6a64,
		  0x7b280000, 0x57420000, 0xa9e50000, 0x634300a0,
		  0x9edb442f, 0x6d9995bb, 0x27f83b03, 0xc7ff60f0 },
		{ 0x00440000, 0x7f480000, 0xda7c0000, 0x2a230001,
		  0x3badc9cc, 0xa9b69c87, 0x030a9e60, 0xbe0a679e,
		  0x5fec0000, 0x294b0000, 0x99d20000, 0x4ed00012,
		  0x1ed34f73, 0xbaa708c9, 0x57140bdf, 0x30aebcf7 },
		{ 0x5fa80000, 0x56030000, 0x43ae0000, 0x64f30013,
		  0x257e86bf, 0x1311944e, 0x541e95bf, 0x8ea4db69,
		  0x00440000, 0x7f480000, 0xda7c0000, 0x2a230001,
		  0x3badc9cc, 0xa9b69c87, 0x030a9e60, 0xbe0a679e },
		{ 0x92280000, 0xdc850000, 0x57fa0000, 0x56dc0003,
		  0xbae92316, 0x5aefa30c, 0x90cef752, 0x7b1675d7,
		  0x93bb0000, 0x3b070000, 0xba010000, 0x99d00008,
		  0x3739ae4e, 0xe64c1722, 0x96f896b3, 0x2879ebac },
		{ 0x01930000, 0xe7820000, 0xedfb0000, 0xcf0c000b,
		  0x8dd08d58, 0xbca3b42e, 0x063661e1, 0x536f9e7b,
		  0x92280000, 0xdc850000, 0x57fa0000, 0x56dc0003,
		  0xbae92316, 0x5aefa30c, 0x90cef752, 0x7b1675d7 },
		{ 0xa8da0000, 0x96be0000, 0x5c1d0000, 0x07da0002,
		  0x7d669583, 0x1f98708a, 0xbb668808, 0xda878000,
		  0xabe70000, 0x9e0d0000, 0xaf270000, 0x3d180005,
		  0x2c4f1fd3, 0x74f61695, 0xb5c347eb, 0x3c5dfffe },
		{ 0x033d0000, 0x08b30000, 0xf33a0000, 0x3ac20007,
		  0x51298a50, 0x6b6e661f, 0x0ea5cfe3, 0xe6da7ffe,
		  0xa8da0000, 0x96be0000, 0x5c1d0000, 0x07da0002,
		  0x7d669583, 0x1f98708a, 0xbb668808, 0xda878000 }
	};

	private static int[][] makeT(int x)
	{
		int[][] T = new int[256][16];
		for (int y = 0; y < 256; y ++) {
			for (int z = 0; z < 16; z ++) {
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

	private static final int[][] T512_0 = makeT(0);
	private static final int[][] T512_1 = makeT(8);
	private static final int[][] T512_2 = makeT(16);
	private static final int[][] T512_3 = makeT(24);
	private static final int[][] T512_4 = makeT(32);
	private static final int[][] T512_5 = makeT(40);
	private static final int[][] T512_6 = makeT(48);
	private static final int[][] T512_7 = makeT(56);

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

	private void process(int b0, int b1, int b2, int b3,
		int b4, int b5, int b6, int b7)
	{
		int[] rp = T512_0[b0];
		int m0 = rp[0x0];
		int m1 = rp[0x1];
		int m2 = rp[0x2];
		int m3 = rp[0x3];
		int m4 = rp[0x4];
		int m5 = rp[0x5];
		int m6 = rp[0x6];
		int m7 = rp[0x7];
		int m8 = rp[0x8];
		int m9 = rp[0x9];
		int mA = rp[0xA];
		int mB = rp[0xB];
		int mC = rp[0xC];
		int mD = rp[0xD];
		int mE = rp[0xE];
		int mF = rp[0xF];
		rp = T512_1[b1];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];
		rp = T512_2[b2];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];
		rp = T512_3[b3];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];
		rp = T512_4[b4];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];
		rp = T512_5[b5];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];
		rp = T512_6[b6];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];
		rp = T512_7[b7];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];

		int c0 = h[0x0];
		int c1 = h[0x1];
		int c2 = h[0x2];
		int c3 = h[0x3];
		int c4 = h[0x4];
		int c5 = h[0x5];
		int c6 = h[0x6];
		int c7 = h[0x7];
		int c8 = h[0x8];
		int c9 = h[0x9];
		int cA = h[0xA];
		int cB = h[0xB];
		int cC = h[0xC];
		int cD = h[0xD];
		int cE = h[0xE];
		int cF = h[0xF];
		int t;

		for (int r = 0; r < 6; r ++) {
			m0 ^= ALPHA_N[0x00];
			m1 ^= ALPHA_N[0x01] ^ r;
			c0 ^= ALPHA_N[0x02];
			c1 ^= ALPHA_N[0x03];
			m2 ^= ALPHA_N[0x04];
			m3 ^= ALPHA_N[0x05];
			c2 ^= ALPHA_N[0x06];
			c3 ^= ALPHA_N[0x07];
			c4 ^= ALPHA_N[0x08];
			c5 ^= ALPHA_N[0x09];
			m4 ^= ALPHA_N[0x0A];
			m5 ^= ALPHA_N[0x0B];
			c6 ^= ALPHA_N[0x0C];
			c7 ^= ALPHA_N[0x0D];
			m6 ^= ALPHA_N[0x0E];
			m7 ^= ALPHA_N[0x0F];
			m8 ^= ALPHA_N[0x10];
			m9 ^= ALPHA_N[0x11];
			c8 ^= ALPHA_N[0x12];
			c9 ^= ALPHA_N[0x13];
			mA ^= ALPHA_N[0x14];
			mB ^= ALPHA_N[0x15];
			cA ^= ALPHA_N[0x16];
			cB ^= ALPHA_N[0x17];
			cC ^= ALPHA_N[0x18];
			cD ^= ALPHA_N[0x19];
			mC ^= ALPHA_N[0x1A];
			mD ^= ALPHA_N[0x1B];
			cE ^= ALPHA_N[0x1C];
			cF ^= ALPHA_N[0x1D];
			mE ^= ALPHA_N[0x1E];
			mF ^= ALPHA_N[0x1F];
			t = m0;
			m0 &= m8;
			m0 ^= cC;
			m8 ^= c4;
			m8 ^= m0;
			cC |= t;
			cC ^= c4;
			t ^= m8;
			c4 = cC;
			cC |= t;
			cC ^= m0;
			m0 &= c4;
			t ^= m0;
			c4 ^= cC;
			c4 ^= t;
			m0 = m8;
			m8 = c4;
			c4 = cC;
			cC = ~t;
			t = m1;
			m1 &= m9;
			m1 ^= cD;
			m9 ^= c5;
			m9 ^= m1;
			cD |= t;
			cD ^= c5;
			t ^= m9;
			c5 = cD;
			cD |= t;
			cD ^= m1;
			m1 &= c5;
			t ^= m1;
			c5 ^= cD;
			c5 ^= t;
			m1 = m9;
			m9 = c5;
			c5 = cD;
			cD = ~t;
			t = c0;
			c0 &= c8;
			c0 ^= mC;
			c8 ^= m4;
			c8 ^= c0;
			mC |= t;
			mC ^= m4;
			t ^= c8;
			m4 = mC;
			mC |= t;
			mC ^= c0;
			c0 &= m4;
			t ^= c0;
			m4 ^= mC;
			m4 ^= t;
			c0 = c8;
			c8 = m4;
			m4 = mC;
			mC = ~t;
			t = c1;
			c1 &= c9;
			c1 ^= mD;
			c9 ^= m5;
			c9 ^= c1;
			mD |= t;
			mD ^= m5;
			t ^= c9;
			m5 = mD;
			mD |= t;
			mD ^= c1;
			c1 &= m5;
			t ^= c1;
			m5 ^= mD;
			m5 ^= t;
			c1 = c9;
			c9 = m5;
			m5 = mD;
			mD = ~t;
			t = m2;
			m2 &= mA;
			m2 ^= cE;
			mA ^= c6;
			mA ^= m2;
			cE |= t;
			cE ^= c6;
			t ^= mA;
			c6 = cE;
			cE |= t;
			cE ^= m2;
			m2 &= c6;
			t ^= m2;
			c6 ^= cE;
			c6 ^= t;
			m2 = mA;
			mA = c6;
			c6 = cE;
			cE = ~t;
			t = m3;
			m3 &= mB;
			m3 ^= cF;
			mB ^= c7;
			mB ^= m3;
			cF |= t;
			cF ^= c7;
			t ^= mB;
			c7 = cF;
			cF |= t;
			cF ^= m3;
			m3 &= c7;
			t ^= m3;
			c7 ^= cF;
			c7 ^= t;
			m3 = mB;
			mB = c7;
			c7 = cF;
			cF = ~t;
			t = c2;
			c2 &= cA;
			c2 ^= mE;
			cA ^= m6;
			cA ^= c2;
			mE |= t;
			mE ^= m6;
			t ^= cA;
			m6 = mE;
			mE |= t;
			mE ^= c2;
			c2 &= m6;
			t ^= c2;
			m6 ^= mE;
			m6 ^= t;
			c2 = cA;
			cA = m6;
			m6 = mE;
			mE = ~t;
			t = c3;
			c3 &= cB;
			c3 ^= mF;
			cB ^= m7;
			cB ^= c3;
			mF |= t;
			mF ^= m7;
			t ^= cB;
			m7 = mF;
			mF |= t;
			mF ^= c3;
			c3 &= m7;
			t ^= c3;
			m7 ^= mF;
			m7 ^= t;
			c3 = cB;
			cB = m7;
			m7 = mF;
			mF = ~t;
			m0 = (m0 << 13) | (m0 >>> (32 - 13));
			c8 = (c8 << 3) | (c8 >>> (32 - 3));
			c5 ^= m0 ^ c8;
			mD ^= c8 ^ (m0 << 3);
			c5 = (c5 << 1) | (c5 >>> (32 - 1));
			mD = (mD << 7) | (mD >>> (32 - 7));
			m0 ^= c5 ^ mD;
			c8 ^= mD ^ (c5 << 7);
			m0 = (m0 << 5) | (m0 >>> (32 - 5));
			c8 = (c8 << 22) | (c8 >>> (32 - 22));
			m1 = (m1 << 13) | (m1 >>> (32 - 13));
			c9 = (c9 << 3) | (c9 >>> (32 - 3));
			m4 ^= m1 ^ c9;
			cE ^= c9 ^ (m1 << 3);
			m4 = (m4 << 1) | (m4 >>> (32 - 1));
			cE = (cE << 7) | (cE >>> (32 - 7));
			m1 ^= m4 ^ cE;
			c9 ^= cE ^ (m4 << 7);
			m1 = (m1 << 5) | (m1 >>> (32 - 5));
			c9 = (c9 << 22) | (c9 >>> (32 - 22));
			c0 = (c0 << 13) | (c0 >>> (32 - 13));
			mA = (mA << 3) | (mA >>> (32 - 3));
			m5 ^= c0 ^ mA;
			cF ^= mA ^ (c0 << 3);
			m5 = (m5 << 1) | (m5 >>> (32 - 1));
			cF = (cF << 7) | (cF >>> (32 - 7));
			c0 ^= m5 ^ cF;
			mA ^= cF ^ (m5 << 7);
			c0 = (c0 << 5) | (c0 >>> (32 - 5));
			mA = (mA << 22) | (mA >>> (32 - 22));
			c1 = (c1 << 13) | (c1 >>> (32 - 13));
			mB = (mB << 3) | (mB >>> (32 - 3));
			c6 ^= c1 ^ mB;
			mE ^= mB ^ (c1 << 3);
			c6 = (c6 << 1) | (c6 >>> (32 - 1));
			mE = (mE << 7) | (mE >>> (32 - 7));
			c1 ^= c6 ^ mE;
			mB ^= mE ^ (c6 << 7);
			c1 = (c1 << 5) | (c1 >>> (32 - 5));
			mB = (mB << 22) | (mB >>> (32 - 22));
			m2 = (m2 << 13) | (m2 >>> (32 - 13));
			cA = (cA << 3) | (cA >>> (32 - 3));
			c7 ^= m2 ^ cA;
			mF ^= cA ^ (m2 << 3);
			c7 = (c7 << 1) | (c7 >>> (32 - 1));
			mF = (mF << 7) | (mF >>> (32 - 7));
			m2 ^= c7 ^ mF;
			cA ^= mF ^ (c7 << 7);
			m2 = (m2 << 5) | (m2 >>> (32 - 5));
			cA = (cA << 22) | (cA >>> (32 - 22));
			m3 = (m3 << 13) | (m3 >>> (32 - 13));
			cB = (cB << 3) | (cB >>> (32 - 3));
			m6 ^= m3 ^ cB;
			cC ^= cB ^ (m3 << 3);
			m6 = (m6 << 1) | (m6 >>> (32 - 1));
			cC = (cC << 7) | (cC >>> (32 - 7));
			m3 ^= m6 ^ cC;
			cB ^= cC ^ (m6 << 7);
			m3 = (m3 << 5) | (m3 >>> (32 - 5));
			cB = (cB << 22) | (cB >>> (32 - 22));
			c2 = (c2 << 13) | (c2 >>> (32 - 13));
			m8 = (m8 << 3) | (m8 >>> (32 - 3));
			m7 ^= c2 ^ m8;
			cD ^= m8 ^ (c2 << 3);
			m7 = (m7 << 1) | (m7 >>> (32 - 1));
			cD = (cD << 7) | (cD >>> (32 - 7));
			c2 ^= m7 ^ cD;
			m8 ^= cD ^ (m7 << 7);
			c2 = (c2 << 5) | (c2 >>> (32 - 5));
			m8 = (m8 << 22) | (m8 >>> (32 - 22));
			c3 = (c3 << 13) | (c3 >>> (32 - 13));
			m9 = (m9 << 3) | (m9 >>> (32 - 3));
			c4 ^= c3 ^ m9;
			mC ^= m9 ^ (c3 << 3);
			c4 = (c4 << 1) | (c4 >>> (32 - 1));
			mC = (mC << 7) | (mC >>> (32 - 7));
			c3 ^= c4 ^ mC;
			m9 ^= mC ^ (c4 << 7);
			c3 = (c3 << 5) | (c3 >>> (32 - 5));
			m9 = (m9 << 22) | (m9 >>> (32 - 22));
			m0 = (m0 << 13) | (m0 >>> (32 - 13));
			m3 = (m3 << 3) | (m3 >>> (32 - 3));
			c0 ^= m0 ^ m3;
			c3 ^= m3 ^ (m0 << 3);
			c0 = (c0 << 1) | (c0 >>> (32 - 1));
			c3 = (c3 << 7) | (c3 >>> (32 - 7));
			m0 ^= c0 ^ c3;
			m3 ^= c3 ^ (c0 << 7);
			m0 = (m0 << 5) | (m0 >>> (32 - 5));
			m3 = (m3 << 22) | (m3 >>> (32 - 22));
			m8 = (m8 << 13) | (m8 >>> (32 - 13));
			mB = (mB << 3) | (mB >>> (32 - 3));
			c9 ^= m8 ^ mB;
			cA ^= mB ^ (m8 << 3);
			c9 = (c9 << 1) | (c9 >>> (32 - 1));
			cA = (cA << 7) | (cA >>> (32 - 7));
			m8 ^= c9 ^ cA;
			mB ^= cA ^ (c9 << 7);
			m8 = (m8 << 5) | (m8 >>> (32 - 5));
			mB = (mB << 22) | (mB >>> (32 - 22));
			c5 = (c5 << 13) | (c5 >>> (32 - 13));
			c6 = (c6 << 3) | (c6 >>> (32 - 3));
			m5 ^= c5 ^ c6;
			m6 ^= c6 ^ (c5 << 3);
			m5 = (m5 << 1) | (m5 >>> (32 - 1));
			m6 = (m6 << 7) | (m6 >>> (32 - 7));
			c5 ^= m5 ^ m6;
			c6 ^= m6 ^ (m5 << 7);
			c5 = (c5 << 5) | (c5 >>> (32 - 5));
			c6 = (c6 << 22) | (c6 >>> (32 - 22));
			cD = (cD << 13) | (cD >>> (32 - 13));
			cE = (cE << 3) | (cE >>> (32 - 3));
			mC ^= cD ^ cE;
			mF ^= cE ^ (cD << 3);
			mC = (mC << 1) | (mC >>> (32 - 1));
			mF = (mF << 7) | (mF >>> (32 - 7));
			cD ^= mC ^ mF;
			cE ^= mF ^ (mC << 7);
			cD = (cD << 5) | (cD >>> (32 - 5));
			cE = (cE << 22) | (cE >>> (32 - 22));
		}

		h[0xF] ^= cB;
		h[0xE] ^= cA;
		h[0xD] ^= mB;
		h[0xC] ^= mA;
		h[0xB] ^= c9;
		h[0xA] ^= c8;
		h[0x9] ^= m9;
		h[0x8] ^= m8;
		h[0x7] ^= c3;
		h[0x6] ^= c2;
		h[0x5] ^= m3;
		h[0x4] ^= m2;
		h[0x3] ^= c1;
		h[0x2] ^= c0;
		h[0x1] ^= m1;
		h[0x0] ^= m0;
	}

	private void processFinal(int b0, int b1, int b2, int b3,
		int b4, int b5, int b6, int b7)
	{
		int[] rp = T512_0[b0];
		int m0 = rp[0x0];
		int m1 = rp[0x1];
		int m2 = rp[0x2];
		int m3 = rp[0x3];
		int m4 = rp[0x4];
		int m5 = rp[0x5];
		int m6 = rp[0x6];
		int m7 = rp[0x7];
		int m8 = rp[0x8];
		int m9 = rp[0x9];
		int mA = rp[0xA];
		int mB = rp[0xB];
		int mC = rp[0xC];
		int mD = rp[0xD];
		int mE = rp[0xE];
		int mF = rp[0xF];
		rp = T512_1[b1];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];
		rp = T512_2[b2];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];
		rp = T512_3[b3];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];
		rp = T512_4[b4];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];
		rp = T512_5[b5];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];
		rp = T512_6[b6];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];
		rp = T512_7[b7];
		m0 ^= rp[0x0];
		m1 ^= rp[0x1];
		m2 ^= rp[0x2];
		m3 ^= rp[0x3];
		m4 ^= rp[0x4];
		m5 ^= rp[0x5];
		m6 ^= rp[0x6];
		m7 ^= rp[0x7];
		m8 ^= rp[0x8];
		m9 ^= rp[0x9];
		mA ^= rp[0xA];
		mB ^= rp[0xB];
		mC ^= rp[0xC];
		mD ^= rp[0xD];
		mE ^= rp[0xE];
		mF ^= rp[0xF];

		int c0 = h[0x0];
		int c1 = h[0x1];
		int c2 = h[0x2];
		int c3 = h[0x3];
		int c4 = h[0x4];
		int c5 = h[0x5];
		int c6 = h[0x6];
		int c7 = h[0x7];
		int c8 = h[0x8];
		int c9 = h[0x9];
		int cA = h[0xA];
		int cB = h[0xB];
		int cC = h[0xC];
		int cD = h[0xD];
		int cE = h[0xE];
		int cF = h[0xF];
		int t;

		for (int r = 0; r < 12; r ++) {
			m0 ^= ALPHA_F[0x00];
			m1 ^= ALPHA_F[0x01] ^ r;
			c0 ^= ALPHA_F[0x02];
			c1 ^= ALPHA_F[0x03];
			m2 ^= ALPHA_F[0x04];
			m3 ^= ALPHA_F[0x05];
			c2 ^= ALPHA_F[0x06];
			c3 ^= ALPHA_F[0x07];
			c4 ^= ALPHA_F[0x08];
			c5 ^= ALPHA_F[0x09];
			m4 ^= ALPHA_F[0x0A];
			m5 ^= ALPHA_F[0x0B];
			c6 ^= ALPHA_F[0x0C];
			c7 ^= ALPHA_F[0x0D];
			m6 ^= ALPHA_F[0x0E];
			m7 ^= ALPHA_F[0x0F];
			m8 ^= ALPHA_F[0x10];
			m9 ^= ALPHA_F[0x11];
			c8 ^= ALPHA_F[0x12];
			c9 ^= ALPHA_F[0x13];
			mA ^= ALPHA_F[0x14];
			mB ^= ALPHA_F[0x15];
			cA ^= ALPHA_F[0x16];
			cB ^= ALPHA_F[0x17];
			cC ^= ALPHA_F[0x18];
			cD ^= ALPHA_F[0x19];
			mC ^= ALPHA_F[0x1A];
			mD ^= ALPHA_F[0x1B];
			cE ^= ALPHA_F[0x1C];
			cF ^= ALPHA_F[0x1D];
			mE ^= ALPHA_F[0x1E];
			mF ^= ALPHA_F[0x1F];
			t = m0;
			m0 &= m8;
			m0 ^= cC;
			m8 ^= c4;
			m8 ^= m0;
			cC |= t;
			cC ^= c4;
			t ^= m8;
			c4 = cC;
			cC |= t;
			cC ^= m0;
			m0 &= c4;
			t ^= m0;
			c4 ^= cC;
			c4 ^= t;
			m0 = m8;
			m8 = c4;
			c4 = cC;
			cC = ~t;
			t = m1;
			m1 &= m9;
			m1 ^= cD;
			m9 ^= c5;
			m9 ^= m1;
			cD |= t;
			cD ^= c5;
			t ^= m9;
			c5 = cD;
			cD |= t;
			cD ^= m1;
			m1 &= c5;
			t ^= m1;
			c5 ^= cD;
			c5 ^= t;
			m1 = m9;
			m9 = c5;
			c5 = cD;
			cD = ~t;
			t = c0;
			c0 &= c8;
			c0 ^= mC;
			c8 ^= m4;
			c8 ^= c0;
			mC |= t;
			mC ^= m4;
			t ^= c8;
			m4 = mC;
			mC |= t;
			mC ^= c0;
			c0 &= m4;
			t ^= c0;
			m4 ^= mC;
			m4 ^= t;
			c0 = c8;
			c8 = m4;
			m4 = mC;
			mC = ~t;
			t = c1;
			c1 &= c9;
			c1 ^= mD;
			c9 ^= m5;
			c9 ^= c1;
			mD |= t;
			mD ^= m5;
			t ^= c9;
			m5 = mD;
			mD |= t;
			mD ^= c1;
			c1 &= m5;
			t ^= c1;
			m5 ^= mD;
			m5 ^= t;
			c1 = c9;
			c9 = m5;
			m5 = mD;
			mD = ~t;
			t = m2;
			m2 &= mA;
			m2 ^= cE;
			mA ^= c6;
			mA ^= m2;
			cE |= t;
			cE ^= c6;
			t ^= mA;
			c6 = cE;
			cE |= t;
			cE ^= m2;
			m2 &= c6;
			t ^= m2;
			c6 ^= cE;
			c6 ^= t;
			m2 = mA;
			mA = c6;
			c6 = cE;
			cE = ~t;
			t = m3;
			m3 &= mB;
			m3 ^= cF;
			mB ^= c7;
			mB ^= m3;
			cF |= t;
			cF ^= c7;
			t ^= mB;
			c7 = cF;
			cF |= t;
			cF ^= m3;
			m3 &= c7;
			t ^= m3;
			c7 ^= cF;
			c7 ^= t;
			m3 = mB;
			mB = c7;
			c7 = cF;
			cF = ~t;
			t = c2;
			c2 &= cA;
			c2 ^= mE;
			cA ^= m6;
			cA ^= c2;
			mE |= t;
			mE ^= m6;
			t ^= cA;
			m6 = mE;
			mE |= t;
			mE ^= c2;
			c2 &= m6;
			t ^= c2;
			m6 ^= mE;
			m6 ^= t;
			c2 = cA;
			cA = m6;
			m6 = mE;
			mE = ~t;
			t = c3;
			c3 &= cB;
			c3 ^= mF;
			cB ^= m7;
			cB ^= c3;
			mF |= t;
			mF ^= m7;
			t ^= cB;
			m7 = mF;
			mF |= t;
			mF ^= c3;
			c3 &= m7;
			t ^= c3;
			m7 ^= mF;
			m7 ^= t;
			c3 = cB;
			cB = m7;
			m7 = mF;
			mF = ~t;
			m0 = (m0 << 13) | (m0 >>> (32 - 13));
			c8 = (c8 << 3) | (c8 >>> (32 - 3));
			c5 ^= m0 ^ c8;
			mD ^= c8 ^ (m0 << 3);
			c5 = (c5 << 1) | (c5 >>> (32 - 1));
			mD = (mD << 7) | (mD >>> (32 - 7));
			m0 ^= c5 ^ mD;
			c8 ^= mD ^ (c5 << 7);
			m0 = (m0 << 5) | (m0 >>> (32 - 5));
			c8 = (c8 << 22) | (c8 >>> (32 - 22));
			m1 = (m1 << 13) | (m1 >>> (32 - 13));
			c9 = (c9 << 3) | (c9 >>> (32 - 3));
			m4 ^= m1 ^ c9;
			cE ^= c9 ^ (m1 << 3);
			m4 = (m4 << 1) | (m4 >>> (32 - 1));
			cE = (cE << 7) | (cE >>> (32 - 7));
			m1 ^= m4 ^ cE;
			c9 ^= cE ^ (m4 << 7);
			m1 = (m1 << 5) | (m1 >>> (32 - 5));
			c9 = (c9 << 22) | (c9 >>> (32 - 22));
			c0 = (c0 << 13) | (c0 >>> (32 - 13));
			mA = (mA << 3) | (mA >>> (32 - 3));
			m5 ^= c0 ^ mA;
			cF ^= mA ^ (c0 << 3);
			m5 = (m5 << 1) | (m5 >>> (32 - 1));
			cF = (cF << 7) | (cF >>> (32 - 7));
			c0 ^= m5 ^ cF;
			mA ^= cF ^ (m5 << 7);
			c0 = (c0 << 5) | (c0 >>> (32 - 5));
			mA = (mA << 22) | (mA >>> (32 - 22));
			c1 = (c1 << 13) | (c1 >>> (32 - 13));
			mB = (mB << 3) | (mB >>> (32 - 3));
			c6 ^= c1 ^ mB;
			mE ^= mB ^ (c1 << 3);
			c6 = (c6 << 1) | (c6 >>> (32 - 1));
			mE = (mE << 7) | (mE >>> (32 - 7));
			c1 ^= c6 ^ mE;
			mB ^= mE ^ (c6 << 7);
			c1 = (c1 << 5) | (c1 >>> (32 - 5));
			mB = (mB << 22) | (mB >>> (32 - 22));
			m2 = (m2 << 13) | (m2 >>> (32 - 13));
			cA = (cA << 3) | (cA >>> (32 - 3));
			c7 ^= m2 ^ cA;
			mF ^= cA ^ (m2 << 3);
			c7 = (c7 << 1) | (c7 >>> (32 - 1));
			mF = (mF << 7) | (mF >>> (32 - 7));
			m2 ^= c7 ^ mF;
			cA ^= mF ^ (c7 << 7);
			m2 = (m2 << 5) | (m2 >>> (32 - 5));
			cA = (cA << 22) | (cA >>> (32 - 22));
			m3 = (m3 << 13) | (m3 >>> (32 - 13));
			cB = (cB << 3) | (cB >>> (32 - 3));
			m6 ^= m3 ^ cB;
			cC ^= cB ^ (m3 << 3);
			m6 = (m6 << 1) | (m6 >>> (32 - 1));
			cC = (cC << 7) | (cC >>> (32 - 7));
			m3 ^= m6 ^ cC;
			cB ^= cC ^ (m6 << 7);
			m3 = (m3 << 5) | (m3 >>> (32 - 5));
			cB = (cB << 22) | (cB >>> (32 - 22));
			c2 = (c2 << 13) | (c2 >>> (32 - 13));
			m8 = (m8 << 3) | (m8 >>> (32 - 3));
			m7 ^= c2 ^ m8;
			cD ^= m8 ^ (c2 << 3);
			m7 = (m7 << 1) | (m7 >>> (32 - 1));
			cD = (cD << 7) | (cD >>> (32 - 7));
			c2 ^= m7 ^ cD;
			m8 ^= cD ^ (m7 << 7);
			c2 = (c2 << 5) | (c2 >>> (32 - 5));
			m8 = (m8 << 22) | (m8 >>> (32 - 22));
			c3 = (c3 << 13) | (c3 >>> (32 - 13));
			m9 = (m9 << 3) | (m9 >>> (32 - 3));
			c4 ^= c3 ^ m9;
			mC ^= m9 ^ (c3 << 3);
			c4 = (c4 << 1) | (c4 >>> (32 - 1));
			mC = (mC << 7) | (mC >>> (32 - 7));
			c3 ^= c4 ^ mC;
			m9 ^= mC ^ (c4 << 7);
			c3 = (c3 << 5) | (c3 >>> (32 - 5));
			m9 = (m9 << 22) | (m9 >>> (32 - 22));
			m0 = (m0 << 13) | (m0 >>> (32 - 13));
			m3 = (m3 << 3) | (m3 >>> (32 - 3));
			c0 ^= m0 ^ m3;
			c3 ^= m3 ^ (m0 << 3);
			c0 = (c0 << 1) | (c0 >>> (32 - 1));
			c3 = (c3 << 7) | (c3 >>> (32 - 7));
			m0 ^= c0 ^ c3;
			m3 ^= c3 ^ (c0 << 7);
			m0 = (m0 << 5) | (m0 >>> (32 - 5));
			m3 = (m3 << 22) | (m3 >>> (32 - 22));
			m8 = (m8 << 13) | (m8 >>> (32 - 13));
			mB = (mB << 3) | (mB >>> (32 - 3));
			c9 ^= m8 ^ mB;
			cA ^= mB ^ (m8 << 3);
			c9 = (c9 << 1) | (c9 >>> (32 - 1));
			cA = (cA << 7) | (cA >>> (32 - 7));
			m8 ^= c9 ^ cA;
			mB ^= cA ^ (c9 << 7);
			m8 = (m8 << 5) | (m8 >>> (32 - 5));
			mB = (mB << 22) | (mB >>> (32 - 22));
			c5 = (c5 << 13) | (c5 >>> (32 - 13));
			c6 = (c6 << 3) | (c6 >>> (32 - 3));
			m5 ^= c5 ^ c6;
			m6 ^= c6 ^ (c5 << 3);
			m5 = (m5 << 1) | (m5 >>> (32 - 1));
			m6 = (m6 << 7) | (m6 >>> (32 - 7));
			c5 ^= m5 ^ m6;
			c6 ^= m6 ^ (m5 << 7);
			c5 = (c5 << 5) | (c5 >>> (32 - 5));
			c6 = (c6 << 22) | (c6 >>> (32 - 22));
			cD = (cD << 13) | (cD >>> (32 - 13));
			cE = (cE << 3) | (cE >>> (32 - 3));
			mC ^= cD ^ cE;
			mF ^= cE ^ (cD << 3);
			mC = (mC << 1) | (mC >>> (32 - 1));
			mF = (mF << 7) | (mF >>> (32 - 7));
			cD ^= mC ^ mF;
			cE ^= mF ^ (mC << 7);
			cD = (cD << 5) | (cD >>> (32 - 5));
			cE = (cE << 22) | (cE >>> (32 - 22));
		}

		h[0xF] ^= cB;
		h[0xE] ^= cA;
		h[0xD] ^= mB;
		h[0xC] ^= mA;
		h[0xB] ^= c9;
		h[0xA] ^= c8;
		h[0x9] ^= m9;
		h[0x8] ^= m8;
		h[0x7] ^= c3;
		h[0x6] ^= c2;
		h[0x5] ^= m3;
		h[0x4] ^= m2;
		h[0x3] ^= c1;
		h[0x2] ^= c0;
		h[0x1] ^= m1;
		h[0x0] ^= m0;
	}

	/** @see Digest */
	public String toString()
	{
		return "Hamsi-" + (getDigestLength() << 3);
	}
}
