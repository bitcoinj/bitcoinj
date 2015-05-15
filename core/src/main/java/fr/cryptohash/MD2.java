// $Id: MD2.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the MD2 digest algorithm under the {@link
 * Digest} API, using the {@link DigestEngine} class. MD4 is described
 * in RFC 1319.</p>
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

public class MD2 extends DigestEngine {

	/**
	 * Create the object.
	 */
	public MD2()
	{
	}

	/** Internal "magic" table. */
	private static final int[] S = {
		 41,  46,  67, 201, 162, 216, 124,   1,
		 61,  54,  84, 161, 236, 240,   6,  19,
		 98, 167,   5, 243, 192, 199, 115, 140,
		152, 147,  43, 217, 188,  76, 130, 202,
		 30, 155,  87,  60, 253, 212, 224,  22,
		103,  66, 111,  24, 138,  23, 229,  18,
		190,  78, 196, 214, 218, 158, 222,  73,
		160, 251, 245, 142, 187,  47, 238, 122,
		169, 104, 121, 145,  21, 178,   7,  63,
		148, 194,  16, 137,  11,  34,  95,  33,
		128, 127,  93, 154,  90, 144,  50,  39,
		 53,  62, 204, 231, 191, 247, 151,   3,
		255,  25,  48, 179,  72, 165, 181, 209,
		215,  94, 146,  42, 172,  86, 170, 198,
		 79, 184,  56, 210, 150, 164, 125, 182,
		118, 252, 107, 226, 156, 116,   4, 241,
		 69, 157, 112,  89, 100, 113, 135,  32,
		134,  91, 207, 101, 230,  45, 168,   2,
		 27,  96,  37, 173, 174, 176, 185, 246,
		 28,  70,  97, 105,  52,  64, 126,  15,
		 85,  71, 163,  35, 221,  81, 175,  58,
		195,  92, 249, 206, 186, 197, 234,  38,
		 44,  83,  13, 110, 133,  40, 132,   9,
		211, 223, 205, 244,  65, 129,  77,  82,
		106, 220,  55, 200, 108, 193, 171, 250,
		 36, 225, 123,   8,  12, 189, 177,  74,
		120, 136, 149, 139, 227,  99, 232, 109,
		233, 203, 213, 254,  59,   0,  29,  57,
		242, 239, 183,  14, 102,  88, 208, 228,
		166, 119, 114, 248, 235, 117,  75,  10,
		 49,  68,  80, 180, 143, 237,  31,  26,
		219, 153, 141,  51, 159,  17, 131,  20
	};

	private int[] X, C;
	private byte[] D;
	private int L;

	/** @see Digest */
	public Digest copy()
	{
		MD2 d = new MD2();
		System.arraycopy(X, 0, d.X, 0, X.length);
		System.arraycopy(C, 0, d.C, 0, C.length);
		d.L = L;
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
		return 16;
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		for (int i = 0; i < 16; i ++) {
			X[i] = 0;
			C[i] = 0;
		}
		L = 0;
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		int pending = flush();
		for (int i = 0; i < (16 - pending); i ++)
			update((byte)(16 - pending));
		flush();
		for (int i = 0; i < 16; i ++)
			D[i] = (byte)(C[i]);
		processBlock(D);
		for (int i = 0; i < 16; i ++)
			output[outputOffset + i] = (byte)(X[i]);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		X = new int[48];
		C = new int[16];
		D = new byte[16];
		engineReset();
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		int tL = L;
		for (int i = 0; i < 16; i ++) {
			int u = data[i] & 0xFF;
			X[16 + i] = u;
			X[32 + i] = X[i] ^ u;
			tL = (C[i] ^= S[u ^ tL]);
		}
		L = tL;
		int t = 0;
		for (int j = 0; j < 18; j ++) {
			for (int k = 0; k < 48; k += 8) {
				t = (X[k + 0] ^= S[t]);
				t = (X[k + 1] ^= S[t]);
				t = (X[k + 2] ^= S[t]);
				t = (X[k + 3] ^= S[t]);
				t = (X[k + 4] ^= S[t]);
				t = (X[k + 5] ^= S[t]);
				t = (X[k + 6] ^= S[t]);
				t = (X[k + 7] ^= S[t]);
			}
			t = (t + j) & 0xFF;
		}
	}

	/** @see Digest */
	public String toString()
	{
		return "MD2";
	}
}
