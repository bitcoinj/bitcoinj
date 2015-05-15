// $Id: SkeinSmallCore.java 253 2011-06-07 18:33:10Z tp $

package fr.cryptohash;

/**
 * This class implements the Skein core function when used with a
 * 256-bit internal state ("Skein-256" in the Skein specification
 * terminology). This class is not currently used, since the recommended
 * parameters for the SHA-3 competition call for a 512-bit internal
 * state ("Skein-512") for all output sizes (224, 256, 384 and 512
 * bits).
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

abstract class SkeinSmallCore implements Digest {

	private static final int BLOCK_LEN = 32;

	private byte[] buf, tmpOut;
	private int ptr;
	private long h0, h1, h2, h3;
	private long bcount;

	/**
	 * Create the object.
	 */
	SkeinSmallCore()
	{
		buf = new byte[BLOCK_LEN];
		tmpOut = new byte[BLOCK_LEN];
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
		encodeLELong(h0, tmpOut,  0);
		encodeLELong(h1, tmpOut,  8);
		encodeLELong(h2, tmpOut, 16);
		encodeLELong(h3, tmpOut, 24);
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
		h0 = iv[0];
		h1 = iv[1];
		h2 = iv[2];
		h3 = iv[3];
		bcount = 0L;
	}

	/** @see Digest */
	public Digest copy()
	{
		SkeinSmallCore dst = dup();
		System.arraycopy(buf, 0, dst.buf, 0, ptr);
		dst.ptr = ptr;
		dst.h0 = h0;
		dst.h1 = h1;
		dst.h2 = h2;
		dst.h3 = h3;
		dst.bcount = bcount;
		return dst;
	}

	/** @see Digest */
	public int getBlockLength()
	{
		return BLOCK_LEN;
	}

	abstract SkeinSmallCore dup();

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
		long p0 = m0;
		long p1 = m1;
		long p2 = m2;
		long p3 = m3;
		long h4 = (h0 ^ h1) ^ (h2 ^ h3) ^ 0x1BD11BDAA9FC1A22L;
		long t0 = (bcount << 5) + (long)extra;
		long t1 = (bcount >>> 59) + ((long)etype << 55);
		long t2 = t0 ^ t1;
		p0 += h0;
		p1 += h1 + t0;
		p2 += h2 + t1;
		p3 += h3 + 0L;
		p0 += p1;
		p1 = (p1 << 14) ^ (p1 >>> (64 - 14)) ^ p0;
		p2 += p3;
		p3 = (p3 << 16) ^ (p3 >>> (64 - 16)) ^ p2;
		p0 += p3;
		p3 = (p3 << 52) ^ (p3 >>> (64 - 52)) ^ p0;
		p2 += p1;
		p1 = (p1 << 57) ^ (p1 >>> (64 - 57)) ^ p2;
		p0 += p1;
		p1 = (p1 << 23) ^ (p1 >>> (64 - 23)) ^ p0;
		p2 += p3;
		p3 = (p3 << 40) ^ (p3 >>> (64 - 40)) ^ p2;
		p0 += p3;
		p3 = (p3 << 5) ^ (p3 >>> (64 - 5)) ^ p0;
		p2 += p1;
		p1 = (p1 << 37) ^ (p1 >>> (64 - 37)) ^ p2;
		p0 += h1;
		p1 += h2 + t1;
		p2 += h3 + t2;
		p3 += h4 + 1L;
		p0 += p1;
		p1 = (p1 << 25) ^ (p1 >>> (64 - 25)) ^ p0;
		p2 += p3;
		p3 = (p3 << 33) ^ (p3 >>> (64 - 33)) ^ p2;
		p0 += p3;
		p3 = (p3 << 46) ^ (p3 >>> (64 - 46)) ^ p0;
		p2 += p1;
		p1 = (p1 << 12) ^ (p1 >>> (64 - 12)) ^ p2;
		p0 += p1;
		p1 = (p1 << 58) ^ (p1 >>> (64 - 58)) ^ p0;
		p2 += p3;
		p3 = (p3 << 22) ^ (p3 >>> (64 - 22)) ^ p2;
		p0 += p3;
		p3 = (p3 << 32) ^ (p3 >>> (64 - 32)) ^ p0;
		p2 += p1;
		p1 = (p1 << 32) ^ (p1 >>> (64 - 32)) ^ p2;
		p0 += h2;
		p1 += h3 + t2;
		p2 += h4 + t0;
		p3 += h0 + 2L;
		p0 += p1;
		p1 = (p1 << 14) ^ (p1 >>> (64 - 14)) ^ p0;
		p2 += p3;
		p3 = (p3 << 16) ^ (p3 >>> (64 - 16)) ^ p2;
		p0 += p3;
		p3 = (p3 << 52) ^ (p3 >>> (64 - 52)) ^ p0;
		p2 += p1;
		p1 = (p1 << 57) ^ (p1 >>> (64 - 57)) ^ p2;
		p0 += p1;
		p1 = (p1 << 23) ^ (p1 >>> (64 - 23)) ^ p0;
		p2 += p3;
		p3 = (p3 << 40) ^ (p3 >>> (64 - 40)) ^ p2;
		p0 += p3;
		p3 = (p3 << 5) ^ (p3 >>> (64 - 5)) ^ p0;
		p2 += p1;
		p1 = (p1 << 37) ^ (p1 >>> (64 - 37)) ^ p2;
		p0 += h3;
		p1 += h4 + t0;
		p2 += h0 + t1;
		p3 += h1 + 3L;
		p0 += p1;
		p1 = (p1 << 25) ^ (p1 >>> (64 - 25)) ^ p0;
		p2 += p3;
		p3 = (p3 << 33) ^ (p3 >>> (64 - 33)) ^ p2;
		p0 += p3;
		p3 = (p3 << 46) ^ (p3 >>> (64 - 46)) ^ p0;
		p2 += p1;
		p1 = (p1 << 12) ^ (p1 >>> (64 - 12)) ^ p2;
		p0 += p1;
		p1 = (p1 << 58) ^ (p1 >>> (64 - 58)) ^ p0;
		p2 += p3;
		p3 = (p3 << 22) ^ (p3 >>> (64 - 22)) ^ p2;
		p0 += p3;
		p3 = (p3 << 32) ^ (p3 >>> (64 - 32)) ^ p0;
		p2 += p1;
		p1 = (p1 << 32) ^ (p1 >>> (64 - 32)) ^ p2;
		p0 += h4;
		p1 += h0 + t1;
		p2 += h1 + t2;
		p3 += h2 + 4L;
		p0 += p1;
		p1 = (p1 << 14) ^ (p1 >>> (64 - 14)) ^ p0;
		p2 += p3;
		p3 = (p3 << 16) ^ (p3 >>> (64 - 16)) ^ p2;
		p0 += p3;
		p3 = (p3 << 52) ^ (p3 >>> (64 - 52)) ^ p0;
		p2 += p1;
		p1 = (p1 << 57) ^ (p1 >>> (64 - 57)) ^ p2;
		p0 += p1;
		p1 = (p1 << 23) ^ (p1 >>> (64 - 23)) ^ p0;
		p2 += p3;
		p3 = (p3 << 40) ^ (p3 >>> (64 - 40)) ^ p2;
		p0 += p3;
		p3 = (p3 << 5) ^ (p3 >>> (64 - 5)) ^ p0;
		p2 += p1;
		p1 = (p1 << 37) ^ (p1 >>> (64 - 37)) ^ p2;
		p0 += h0;
		p1 += h1 + t2;
		p2 += h2 + t0;
		p3 += h3 + 5L;
		p0 += p1;
		p1 = (p1 << 25) ^ (p1 >>> (64 - 25)) ^ p0;
		p2 += p3;
		p3 = (p3 << 33) ^ (p3 >>> (64 - 33)) ^ p2;
		p0 += p3;
		p3 = (p3 << 46) ^ (p3 >>> (64 - 46)) ^ p0;
		p2 += p1;
		p1 = (p1 << 12) ^ (p1 >>> (64 - 12)) ^ p2;
		p0 += p1;
		p1 = (p1 << 58) ^ (p1 >>> (64 - 58)) ^ p0;
		p2 += p3;
		p3 = (p3 << 22) ^ (p3 >>> (64 - 22)) ^ p2;
		p0 += p3;
		p3 = (p3 << 32) ^ (p3 >>> (64 - 32)) ^ p0;
		p2 += p1;
		p1 = (p1 << 32) ^ (p1 >>> (64 - 32)) ^ p2;
		p0 += h1;
		p1 += h2 + t0;
		p2 += h3 + t1;
		p3 += h4 + 6L;
		p0 += p1;
		p1 = (p1 << 14) ^ (p1 >>> (64 - 14)) ^ p0;
		p2 += p3;
		p3 = (p3 << 16) ^ (p3 >>> (64 - 16)) ^ p2;
		p0 += p3;
		p3 = (p3 << 52) ^ (p3 >>> (64 - 52)) ^ p0;
		p2 += p1;
		p1 = (p1 << 57) ^ (p1 >>> (64 - 57)) ^ p2;
		p0 += p1;
		p1 = (p1 << 23) ^ (p1 >>> (64 - 23)) ^ p0;
		p2 += p3;
		p3 = (p3 << 40) ^ (p3 >>> (64 - 40)) ^ p2;
		p0 += p3;
		p3 = (p3 << 5) ^ (p3 >>> (64 - 5)) ^ p0;
		p2 += p1;
		p1 = (p1 << 37) ^ (p1 >>> (64 - 37)) ^ p2;
		p0 += h2;
		p1 += h3 + t1;
		p2 += h4 + t2;
		p3 += h0 + 7L;
		p0 += p1;
		p1 = (p1 << 25) ^ (p1 >>> (64 - 25)) ^ p0;
		p2 += p3;
		p3 = (p3 << 33) ^ (p3 >>> (64 - 33)) ^ p2;
		p0 += p3;
		p3 = (p3 << 46) ^ (p3 >>> (64 - 46)) ^ p0;
		p2 += p1;
		p1 = (p1 << 12) ^ (p1 >>> (64 - 12)) ^ p2;
		p0 += p1;
		p1 = (p1 << 58) ^ (p1 >>> (64 - 58)) ^ p0;
		p2 += p3;
		p3 = (p3 << 22) ^ (p3 >>> (64 - 22)) ^ p2;
		p0 += p3;
		p3 = (p3 << 32) ^ (p3 >>> (64 - 32)) ^ p0;
		p2 += p1;
		p1 = (p1 << 32) ^ (p1 >>> (64 - 32)) ^ p2;
		p0 += h3;
		p1 += h4 + t2;
		p2 += h0 + t0;
		p3 += h1 + 8L;
		p0 += p1;
		p1 = (p1 << 14) ^ (p1 >>> (64 - 14)) ^ p0;
		p2 += p3;
		p3 = (p3 << 16) ^ (p3 >>> (64 - 16)) ^ p2;
		p0 += p3;
		p3 = (p3 << 52) ^ (p3 >>> (64 - 52)) ^ p0;
		p2 += p1;
		p1 = (p1 << 57) ^ (p1 >>> (64 - 57)) ^ p2;
		p0 += p1;
		p1 = (p1 << 23) ^ (p1 >>> (64 - 23)) ^ p0;
		p2 += p3;
		p3 = (p3 << 40) ^ (p3 >>> (64 - 40)) ^ p2;
		p0 += p3;
		p3 = (p3 << 5) ^ (p3 >>> (64 - 5)) ^ p0;
		p2 += p1;
		p1 = (p1 << 37) ^ (p1 >>> (64 - 37)) ^ p2;
		p0 += h4;
		p1 += h0 + t0;
		p2 += h1 + t1;
		p3 += h2 + 9L;
		p0 += p1;
		p1 = (p1 << 25) ^ (p1 >>> (64 - 25)) ^ p0;
		p2 += p3;
		p3 = (p3 << 33) ^ (p3 >>> (64 - 33)) ^ p2;
		p0 += p3;
		p3 = (p3 << 46) ^ (p3 >>> (64 - 46)) ^ p0;
		p2 += p1;
		p1 = (p1 << 12) ^ (p1 >>> (64 - 12)) ^ p2;
		p0 += p1;
		p1 = (p1 << 58) ^ (p1 >>> (64 - 58)) ^ p0;
		p2 += p3;
		p3 = (p3 << 22) ^ (p3 >>> (64 - 22)) ^ p2;
		p0 += p3;
		p3 = (p3 << 32) ^ (p3 >>> (64 - 32)) ^ p0;
		p2 += p1;
		p1 = (p1 << 32) ^ (p1 >>> (64 - 32)) ^ p2;
		p0 += h0;
		p1 += h1 + t1;
		p2 += h2 + t2;
		p3 += h3 + 10L;
		p0 += p1;
		p1 = (p1 << 14) ^ (p1 >>> (64 - 14)) ^ p0;
		p2 += p3;
		p3 = (p3 << 16) ^ (p3 >>> (64 - 16)) ^ p2;
		p0 += p3;
		p3 = (p3 << 52) ^ (p3 >>> (64 - 52)) ^ p0;
		p2 += p1;
		p1 = (p1 << 57) ^ (p1 >>> (64 - 57)) ^ p2;
		p0 += p1;
		p1 = (p1 << 23) ^ (p1 >>> (64 - 23)) ^ p0;
		p2 += p3;
		p3 = (p3 << 40) ^ (p3 >>> (64 - 40)) ^ p2;
		p0 += p3;
		p3 = (p3 << 5) ^ (p3 >>> (64 - 5)) ^ p0;
		p2 += p1;
		p1 = (p1 << 37) ^ (p1 >>> (64 - 37)) ^ p2;
		p0 += h1;
		p1 += h2 + t2;
		p2 += h3 + t0;
		p3 += h4 + 11L;
		p0 += p1;
		p1 = (p1 << 25) ^ (p1 >>> (64 - 25)) ^ p0;
		p2 += p3;
		p3 = (p3 << 33) ^ (p3 >>> (64 - 33)) ^ p2;
		p0 += p3;
		p3 = (p3 << 46) ^ (p3 >>> (64 - 46)) ^ p0;
		p2 += p1;
		p1 = (p1 << 12) ^ (p1 >>> (64 - 12)) ^ p2;
		p0 += p1;
		p1 = (p1 << 58) ^ (p1 >>> (64 - 58)) ^ p0;
		p2 += p3;
		p3 = (p3 << 22) ^ (p3 >>> (64 - 22)) ^ p2;
		p0 += p3;
		p3 = (p3 << 32) ^ (p3 >>> (64 - 32)) ^ p0;
		p2 += p1;
		p1 = (p1 << 32) ^ (p1 >>> (64 - 32)) ^ p2;
		p0 += h2;
		p1 += h3 + t0;
		p2 += h4 + t1;
		p3 += h0 + 12L;
		p0 += p1;
		p1 = (p1 << 14) ^ (p1 >>> (64 - 14)) ^ p0;
		p2 += p3;
		p3 = (p3 << 16) ^ (p3 >>> (64 - 16)) ^ p2;
		p0 += p3;
		p3 = (p3 << 52) ^ (p3 >>> (64 - 52)) ^ p0;
		p2 += p1;
		p1 = (p1 << 57) ^ (p1 >>> (64 - 57)) ^ p2;
		p0 += p1;
		p1 = (p1 << 23) ^ (p1 >>> (64 - 23)) ^ p0;
		p2 += p3;
		p3 = (p3 << 40) ^ (p3 >>> (64 - 40)) ^ p2;
		p0 += p3;
		p3 = (p3 << 5) ^ (p3 >>> (64 - 5)) ^ p0;
		p2 += p1;
		p1 = (p1 << 37) ^ (p1 >>> (64 - 37)) ^ p2;
		p0 += h3;
		p1 += h4 + t1;
		p2 += h0 + t2;
		p3 += h1 + 13L;
		p0 += p1;
		p1 = (p1 << 25) ^ (p1 >>> (64 - 25)) ^ p0;
		p2 += p3;
		p3 = (p3 << 33) ^ (p3 >>> (64 - 33)) ^ p2;
		p0 += p3;
		p3 = (p3 << 46) ^ (p3 >>> (64 - 46)) ^ p0;
		p2 += p1;
		p1 = (p1 << 12) ^ (p1 >>> (64 - 12)) ^ p2;
		p0 += p1;
		p1 = (p1 << 58) ^ (p1 >>> (64 - 58)) ^ p0;
		p2 += p3;
		p3 = (p3 << 22) ^ (p3 >>> (64 - 22)) ^ p2;
		p0 += p3;
		p3 = (p3 << 32) ^ (p3 >>> (64 - 32)) ^ p0;
		p2 += p1;
		p1 = (p1 << 32) ^ (p1 >>> (64 - 32)) ^ p2;
		p0 += h4;
		p1 += h0 + t2;
		p2 += h1 + t0;
		p3 += h2 + 14L;
		p0 += p1;
		p1 = (p1 << 14) ^ (p1 >>> (64 - 14)) ^ p0;
		p2 += p3;
		p3 = (p3 << 16) ^ (p3 >>> (64 - 16)) ^ p2;
		p0 += p3;
		p3 = (p3 << 52) ^ (p3 >>> (64 - 52)) ^ p0;
		p2 += p1;
		p1 = (p1 << 57) ^ (p1 >>> (64 - 57)) ^ p2;
		p0 += p1;
		p1 = (p1 << 23) ^ (p1 >>> (64 - 23)) ^ p0;
		p2 += p3;
		p3 = (p3 << 40) ^ (p3 >>> (64 - 40)) ^ p2;
		p0 += p3;
		p3 = (p3 << 5) ^ (p3 >>> (64 - 5)) ^ p0;
		p2 += p1;
		p1 = (p1 << 37) ^ (p1 >>> (64 - 37)) ^ p2;
		p0 += h0;
		p1 += h1 + t0;
		p2 += h2 + t1;
		p3 += h3 + 15L;
		p0 += p1;
		p1 = (p1 << 25) ^ (p1 >>> (64 - 25)) ^ p0;
		p2 += p3;
		p3 = (p3 << 33) ^ (p3 >>> (64 - 33)) ^ p2;
		p0 += p3;
		p3 = (p3 << 46) ^ (p3 >>> (64 - 46)) ^ p0;
		p2 += p1;
		p1 = (p1 << 12) ^ (p1 >>> (64 - 12)) ^ p2;
		p0 += p1;
		p1 = (p1 << 58) ^ (p1 >>> (64 - 58)) ^ p0;
		p2 += p3;
		p3 = (p3 << 22) ^ (p3 >>> (64 - 22)) ^ p2;
		p0 += p3;
		p3 = (p3 << 32) ^ (p3 >>> (64 - 32)) ^ p0;
		p2 += p1;
		p1 = (p1 << 32) ^ (p1 >>> (64 - 32)) ^ p2;
		p0 += h1;
		p1 += h2 + t1;
		p2 += h3 + t2;
		p3 += h4 + 16L;
		p0 += p1;
		p1 = (p1 << 14) ^ (p1 >>> (64 - 14)) ^ p0;
		p2 += p3;
		p3 = (p3 << 16) ^ (p3 >>> (64 - 16)) ^ p2;
		p0 += p3;
		p3 = (p3 << 52) ^ (p3 >>> (64 - 52)) ^ p0;
		p2 += p1;
		p1 = (p1 << 57) ^ (p1 >>> (64 - 57)) ^ p2;
		p0 += p1;
		p1 = (p1 << 23) ^ (p1 >>> (64 - 23)) ^ p0;
		p2 += p3;
		p3 = (p3 << 40) ^ (p3 >>> (64 - 40)) ^ p2;
		p0 += p3;
		p3 = (p3 << 5) ^ (p3 >>> (64 - 5)) ^ p0;
		p2 += p1;
		p1 = (p1 << 37) ^ (p1 >>> (64 - 37)) ^ p2;
		p0 += h2;
		p1 += h3 + t2;
		p2 += h4 + t0;
		p3 += h0 + 17L;
		p0 += p1;
		p1 = (p1 << 25) ^ (p1 >>> (64 - 25)) ^ p0;
		p2 += p3;
		p3 = (p3 << 33) ^ (p3 >>> (64 - 33)) ^ p2;
		p0 += p3;
		p3 = (p3 << 46) ^ (p3 >>> (64 - 46)) ^ p0;
		p2 += p1;
		p1 = (p1 << 12) ^ (p1 >>> (64 - 12)) ^ p2;
		p0 += p1;
		p1 = (p1 << 58) ^ (p1 >>> (64 - 58)) ^ p0;
		p2 += p3;
		p3 = (p3 << 22) ^ (p3 >>> (64 - 22)) ^ p2;
		p0 += p3;
		p3 = (p3 << 32) ^ (p3 >>> (64 - 32)) ^ p0;
		p2 += p1;
		p1 = (p1 << 32) ^ (p1 >>> (64 - 32)) ^ p2;
		p0 += h3;
		p1 += h4 + t0;
		p2 += h0 + t1;
		p3 += h1 + 18L;
		h0 = m0 ^ p0;
		h1 = m1 ^ p1;
		h2 = m2 ^ p2;
		h3 = m3 ^ p3;
	}

	/** @see Digest */
	public String toString()
	{
		return "Skein-" + (getDigestLength() << 3);
	}
}
