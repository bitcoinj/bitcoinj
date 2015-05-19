// $Id: SkeinBigCore.java 253 2011-06-07 18:33:10Z tp $

package fr.cryptohash;

/**
 * This class implements the Skein core with a 512-bit internal state
 * ("Skein-512" in the Skein specification terminology). This is used
 * for Skein-224, Skein-256, Skein-384 and Skein-512 (the SHA-3
 * candidates).
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
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class SkeinBigCore implements Digest {

	private static final int BLOCK_LEN = 64;

	private byte[] buf, tmpOut;
	private int ptr;
	private long[] h;
	private long bcount;

	/**
	 * Create the object.
	 */
	SkeinBigCore()
	{
		buf = new byte[BLOCK_LEN];
		tmpOut = new byte[BLOCK_LEN];
		h = new long[27];
		reset();
	}

	/** @see Digest */
	public void update(byte in)
	{
		if (ptr == BLOCK_LEN) {
			int etype = (bcount == 0) ? 224 : 96;
			bcount ++;
			ubi(etype, 0);
			buf[0] = in;
			ptr = 1;
		} else {
			buf[ptr ++] = in;
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
		if (len <= 0)
			return;
		int clen = BLOCK_LEN - ptr;
		if (len <= clen) {
			System.arraycopy(inbuf, off, buf, ptr, len);
			ptr += len;
			return;
		}
		if (clen != 0) {
			System.arraycopy(inbuf, off, buf, ptr, clen);
			off += clen;
			len -= clen;
		}

		for (;;) {
			int etype = (bcount == 0) ? 224 : 96;
			bcount ++;
			ubi(etype, 0);
			if (len <= BLOCK_LEN)
				break;
			System.arraycopy(inbuf, off, buf, 0, BLOCK_LEN);
			off += BLOCK_LEN;
			len -= BLOCK_LEN;
		}
		System.arraycopy(inbuf, off, buf, 0, len);
		ptr = len;
	}

	/** @see Digest */
	public byte[] digest()
	{
		int len = getDigestLength();
		byte[] out = new byte[len];
		digest(out, 0, len);
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
		for (int i = ptr; i < BLOCK_LEN; i ++)
			buf[i] = 0x00;
		ubi((bcount == 0) ? 480 : 352, ptr);
		for (int i = 0; i < BLOCK_LEN; i ++)
			buf[i] = 0x00;
		bcount = 0L;
		ubi(510, 8);
		for (int i = 0; i < 8; i ++)
			encodeLELong(h[i], tmpOut, i << 3);
		int dlen = getDigestLength();
		if (len > dlen)
			len = dlen;
		System.arraycopy(tmpOut, 0, outbuf, off, len);
		reset();
		return len;
	}

	/** @see Digest */
	public void reset()
	{
		ptr = 0;
		long[] iv = getInitVal();
		System.arraycopy(iv, 0, h, 0, 8);
		bcount = 0L;
	}

	/** @see Digest */
	public Digest copy()
	{
		SkeinBigCore dst = dup();
		System.arraycopy(buf, 0, dst.buf, 0, ptr);
		dst.ptr = ptr;
		System.arraycopy(h, 0, dst.h, 0, 8);
		dst.bcount = bcount;
		return dst;
	}

	/** @see Digest */
	public int getBlockLength()
	{
		return BLOCK_LEN;
	}

	abstract SkeinBigCore dup();

	/**
	 * Get the initial value for this algorithm.
	 *
	 * @return  the initial value
	 */
	abstract long[] getInitVal();

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

	private static final long decodeLELong(byte[] buf, int off)
	{
		return (long)(buf[off] & 0xFF)
			| ((long)(buf[off + 1] & 0xFF) << 8)
			| ((long)(buf[off + 2] & 0xFF) << 16)
			| ((long)(buf[off + 3] & 0xFF) << 24)
			| ((long)(buf[off + 4] & 0xFF) << 32)
			| ((long)(buf[off + 5] & 0xFF) << 40)
			| ((long)(buf[off + 6] & 0xFF) << 48)
			| ((long)(buf[off + 7] & 0xFF) << 56);
	}

	private final void ubi(int etype, int extra)
	{
		long m0 = decodeLELong(buf,  0);
		long m1 = decodeLELong(buf,  8);
		long m2 = decodeLELong(buf, 16);
		long m3 = decodeLELong(buf, 24);
		long m4 = decodeLELong(buf, 32);
		long m5 = decodeLELong(buf, 40);
		long m6 = decodeLELong(buf, 48);
		long m7 = decodeLELong(buf, 56);
		long p0 = m0;
		long p1 = m1;
		long p2 = m2;
		long p3 = m3;
		long p4 = m4;
		long p5 = m5;
		long p6 = m6;
		long p7 = m7;
		h[8] = ((h[0] ^ h[1]) ^ (h[2] ^ h[3]))
			^ ((h[4] ^ h[5]) ^ (h[6] ^ h[7])) ^ 0x1BD11BDAA9FC1A22L;
		long t0 = (bcount << 6) + (long)extra;
		long t1 = (bcount >>> 58) + ((long)etype << 55);
		long t2 = t0 ^ t1;
		for (int u = 0; u <= 15; u += 3) {
			h[u + 9] = h[u + 0];
			h[u + 10] = h[u + 1];
			h[u + 11] = h[u + 2];
		}
		for (int u = 0; u < 9; u++) {
			int s = u << 1;
			p0 += h[s + 0];
			p1 += h[s + 1];
			p2 += h[s + 2];
			p3 += h[s + 3];
			p4 += h[s + 4];
			p5 += h[s + 5] + t0;
			p6 += h[s + 6] + t1;
			p7 += h[s + 7] + s;
			p0 += p1;
			p1 = (p1 << 46) ^ (p1 >>> (64 - 46)) ^ p0;
			p2 += p3;
			p3 = (p3 << 36) ^ (p3 >>> (64 - 36)) ^ p2;
			p4 += p5;
			p5 = (p5 << 19) ^ (p5 >>> (64 - 19)) ^ p4;
			p6 += p7;
			p7 = (p7 << 37) ^ (p7 >>> (64 - 37)) ^ p6;
			p2 += p1;
			p1 = (p1 << 33) ^ (p1 >>> (64 - 33)) ^ p2;
			p4 += p7;
			p7 = (p7 << 27) ^ (p7 >>> (64 - 27)) ^ p4;
			p6 += p5;
			p5 = (p5 << 14) ^ (p5 >>> (64 - 14)) ^ p6;
			p0 += p3;
			p3 = (p3 << 42) ^ (p3 >>> (64 - 42)) ^ p0;
			p4 += p1;
			p1 = (p1 << 17) ^ (p1 >>> (64 - 17)) ^ p4;
			p6 += p3;
			p3 = (p3 << 49) ^ (p3 >>> (64 - 49)) ^ p6;
			p0 += p5;
			p5 = (p5 << 36) ^ (p5 >>> (64 - 36)) ^ p0;
			p2 += p7;
			p7 = (p7 << 39) ^ (p7 >>> (64 - 39)) ^ p2;
			p6 += p1;
			p1 = (p1 << 44) ^ (p1 >>> (64 - 44)) ^ p6;
			p0 += p7;
			p7 = (p7 << 9) ^ (p7 >>> (64 - 9)) ^ p0;
			p2 += p5;
			p5 = (p5 << 54) ^ (p5 >>> (64 - 54)) ^ p2;
			p4 += p3;
			p3 = (p3 << 56) ^ (p3 >>> (64 - 56)) ^ p4;
			p0 += h[s + 1 + 0];
			p1 += h[s + 1 + 1];
			p2 += h[s + 1 + 2];
			p3 += h[s + 1 + 3];
			p4 += h[s + 1 + 4];
			p5 += h[s + 1 + 5] + t1;
			p6 += h[s + 1 + 6] + t2;
			p7 += h[s + 1 + 7] + s + 1;
			p0 += p1;
			p1 = (p1 << 39) ^ (p1 >>> (64 - 39)) ^ p0;
			p2 += p3;
			p3 = (p3 << 30) ^ (p3 >>> (64 - 30)) ^ p2;
			p4 += p5;
			p5 = (p5 << 34) ^ (p5 >>> (64 - 34)) ^ p4;
			p6 += p7;
			p7 = (p7 << 24) ^ (p7 >>> (64 - 24)) ^ p6;
			p2 += p1;
			p1 = (p1 << 13) ^ (p1 >>> (64 - 13)) ^ p2;
			p4 += p7;
			p7 = (p7 << 50) ^ (p7 >>> (64 - 50)) ^ p4;
			p6 += p5;
			p5 = (p5 << 10) ^ (p5 >>> (64 - 10)) ^ p6;
			p0 += p3;
			p3 = (p3 << 17) ^ (p3 >>> (64 - 17)) ^ p0;
			p4 += p1;
			p1 = (p1 << 25) ^ (p1 >>> (64 - 25)) ^ p4;
			p6 += p3;
			p3 = (p3 << 29) ^ (p3 >>> (64 - 29)) ^ p6;
			p0 += p5;
			p5 = (p5 << 39) ^ (p5 >>> (64 - 39)) ^ p0;
			p2 += p7;
			p7 = (p7 << 43) ^ (p7 >>> (64 - 43)) ^ p2;
			p6 += p1;
			p1 = (p1 << 8) ^ (p1 >>> (64 - 8)) ^ p6;
			p0 += p7;
			p7 = (p7 << 35) ^ (p7 >>> (64 - 35)) ^ p0;
			p2 += p5;
			p5 = (p5 << 56) ^ (p5 >>> (64 - 56)) ^ p2;
			p4 += p3;
			p3 = (p3 << 22) ^ (p3 >>> (64 - 22)) ^ p4;
			long tmp = t2;
			t2 = t1;
			t1 = t0;
			t0 = tmp;
		}
		p0 += h[18 + 0];
		p1 += h[18 + 1];
		p2 += h[18 + 2];
		p3 += h[18 + 3];
		p4 += h[18 + 4];
		p5 += h[18 + 5] + t0;
		p6 += h[18 + 6] + t1;
		p7 += h[18 + 7] + 18;
		h[0] = m0 ^ p0;
		h[1] = m1 ^ p1;
		h[2] = m2 ^ p2;
		h[3] = m3 ^ p3;
		h[4] = m4 ^ p4;
		h[5] = m5 ^ p5;
		h[6] = m6 ^ p6;
		h[7] = m7 ^ p7;
	}

	/** @see Digest */
	public String toString()
	{
		return "Skein-" + (getDigestLength() << 3);
	}
}
