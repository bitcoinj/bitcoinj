// $Id: CubeHashCore.java 232 2010-06-17 14:19:24Z tp $

package fr.cryptohash;

/**
 * This class implements the core operations for the CubeHash digest
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
 * @version   $Revision: 232 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class CubeHashCore extends DigestEngine {

	CubeHashCore()
	{
	}

	private int x0, x1, x2, x3, x4, x5, x6, x7;
	private int x8, x9, xa, xb, xc, xd, xe, xf;
	private int xg, xh, xi, xj, xk, xl, xm, xn;
	private int xo, xp, xq, xr, xs, xt, xu, xv;

	private final void inputBlock(byte[] data)
	{
		x0 ^= decodeLEInt(data,  0);
		x1 ^= decodeLEInt(data,  4);
		x2 ^= decodeLEInt(data,  8);
		x3 ^= decodeLEInt(data, 12);
		x4 ^= decodeLEInt(data, 16);
		x5 ^= decodeLEInt(data, 20);
		x6 ^= decodeLEInt(data, 24);
		x7 ^= decodeLEInt(data, 28);
	}

	private final void sixteenRounds()
	{
		for (int i = 0; i < 8; i ++) {
			xg = x0 + xg;
			x0 = (x0 << 7) | (x0 >>> (32 - 7));
			xh = x1 + xh;
			x1 = (x1 << 7) | (x1 >>> (32 - 7));
			xi = x2 + xi;
			x2 = (x2 << 7) | (x2 >>> (32 - 7));
			xj = x3 + xj;
			x3 = (x3 << 7) | (x3 >>> (32 - 7));
			xk = x4 + xk;
			x4 = (x4 << 7) | (x4 >>> (32 - 7));
			xl = x5 + xl;
			x5 = (x5 << 7) | (x5 >>> (32 - 7));
			xm = x6 + xm;
			x6 = (x6 << 7) | (x6 >>> (32 - 7));
			xn = x7 + xn;
			x7 = (x7 << 7) | (x7 >>> (32 - 7));
			xo = x8 + xo;
			x8 = (x8 << 7) | (x8 >>> (32 - 7));
			xp = x9 + xp;
			x9 = (x9 << 7) | (x9 >>> (32 - 7));
			xq = xa + xq;
			xa = (xa << 7) | (xa >>> (32 - 7));
			xr = xb + xr;
			xb = (xb << 7) | (xb >>> (32 - 7));
			xs = xc + xs;
			xc = (xc << 7) | (xc >>> (32 - 7));
			xt = xd + xt;
			xd = (xd << 7) | (xd >>> (32 - 7));
			xu = xe + xu;
			xe = (xe << 7) | (xe >>> (32 - 7));
			xv = xf + xv;
			xf = (xf << 7) | (xf >>> (32 - 7));
			x8 ^= xg;
			x9 ^= xh;
			xa ^= xi;
			xb ^= xj;
			xc ^= xk;
			xd ^= xl;
			xe ^= xm;
			xf ^= xn;
			x0 ^= xo;
			x1 ^= xp;
			x2 ^= xq;
			x3 ^= xr;
			x4 ^= xs;
			x5 ^= xt;
			x6 ^= xu;
			x7 ^= xv;
			xi = x8 + xi;
			x8 = (x8 << 11) | (x8 >>> (32 - 11));
			xj = x9 + xj;
			x9 = (x9 << 11) | (x9 >>> (32 - 11));
			xg = xa + xg;
			xa = (xa << 11) | (xa >>> (32 - 11));
			xh = xb + xh;
			xb = (xb << 11) | (xb >>> (32 - 11));
			xm = xc + xm;
			xc = (xc << 11) | (xc >>> (32 - 11));
			xn = xd + xn;
			xd = (xd << 11) | (xd >>> (32 - 11));
			xk = xe + xk;
			xe = (xe << 11) | (xe >>> (32 - 11));
			xl = xf + xl;
			xf = (xf << 11) | (xf >>> (32 - 11));
			xq = x0 + xq;
			x0 = (x0 << 11) | (x0 >>> (32 - 11));
			xr = x1 + xr;
			x1 = (x1 << 11) | (x1 >>> (32 - 11));
			xo = x2 + xo;
			x2 = (x2 << 11) | (x2 >>> (32 - 11));
			xp = x3 + xp;
			x3 = (x3 << 11) | (x3 >>> (32 - 11));
			xu = x4 + xu;
			x4 = (x4 << 11) | (x4 >>> (32 - 11));
			xv = x5 + xv;
			x5 = (x5 << 11) | (x5 >>> (32 - 11));
			xs = x6 + xs;
			x6 = (x6 << 11) | (x6 >>> (32 - 11));
			xt = x7 + xt;
			x7 = (x7 << 11) | (x7 >>> (32 - 11));
			xc ^= xi;
			xd ^= xj;
			xe ^= xg;
			xf ^= xh;
			x8 ^= xm;
			x9 ^= xn;
			xa ^= xk;
			xb ^= xl;
			x4 ^= xq;
			x5 ^= xr;
			x6 ^= xo;
			x7 ^= xp;
			x0 ^= xu;
			x1 ^= xv;
			x2 ^= xs;
			x3 ^= xt;

			xj = xc + xj;
			xc = (xc << 7) | (xc >>> (32 - 7));
			xi = xd + xi;
			xd = (xd << 7) | (xd >>> (32 - 7));
			xh = xe + xh;
			xe = (xe << 7) | (xe >>> (32 - 7));
			xg = xf + xg;
			xf = (xf << 7) | (xf >>> (32 - 7));
			xn = x8 + xn;
			x8 = (x8 << 7) | (x8 >>> (32 - 7));
			xm = x9 + xm;
			x9 = (x9 << 7) | (x9 >>> (32 - 7));
			xl = xa + xl;
			xa = (xa << 7) | (xa >>> (32 - 7));
			xk = xb + xk;
			xb = (xb << 7) | (xb >>> (32 - 7));
			xr = x4 + xr;
			x4 = (x4 << 7) | (x4 >>> (32 - 7));
			xq = x5 + xq;
			x5 = (x5 << 7) | (x5 >>> (32 - 7));
			xp = x6 + xp;
			x6 = (x6 << 7) | (x6 >>> (32 - 7));
			xo = x7 + xo;
			x7 = (x7 << 7) | (x7 >>> (32 - 7));
			xv = x0 + xv;
			x0 = (x0 << 7) | (x0 >>> (32 - 7));
			xu = x1 + xu;
			x1 = (x1 << 7) | (x1 >>> (32 - 7));
			xt = x2 + xt;
			x2 = (x2 << 7) | (x2 >>> (32 - 7));
			xs = x3 + xs;
			x3 = (x3 << 7) | (x3 >>> (32 - 7));
			x4 ^= xj;
			x5 ^= xi;
			x6 ^= xh;
			x7 ^= xg;
			x0 ^= xn;
			x1 ^= xm;
			x2 ^= xl;
			x3 ^= xk;
			xc ^= xr;
			xd ^= xq;
			xe ^= xp;
			xf ^= xo;
			x8 ^= xv;
			x9 ^= xu;
			xa ^= xt;
			xb ^= xs;
			xh = x4 + xh;
			x4 = (x4 << 11) | (x4 >>> (32 - 11));
			xg = x5 + xg;
			x5 = (x5 << 11) | (x5 >>> (32 - 11));
			xj = x6 + xj;
			x6 = (x6 << 11) | (x6 >>> (32 - 11));
			xi = x7 + xi;
			x7 = (x7 << 11) | (x7 >>> (32 - 11));
			xl = x0 + xl;
			x0 = (x0 << 11) | (x0 >>> (32 - 11));
			xk = x1 + xk;
			x1 = (x1 << 11) | (x1 >>> (32 - 11));
			xn = x2 + xn;
			x2 = (x2 << 11) | (x2 >>> (32 - 11));
			xm = x3 + xm;
			x3 = (x3 << 11) | (x3 >>> (32 - 11));
			xp = xc + xp;
			xc = (xc << 11) | (xc >>> (32 - 11));
			xo = xd + xo;
			xd = (xd << 11) | (xd >>> (32 - 11));
			xr = xe + xr;
			xe = (xe << 11) | (xe >>> (32 - 11));
			xq = xf + xq;
			xf = (xf << 11) | (xf >>> (32 - 11));
			xt = x8 + xt;
			x8 = (x8 << 11) | (x8 >>> (32 - 11));
			xs = x9 + xs;
			x9 = (x9 << 11) | (x9 >>> (32 - 11));
			xv = xa + xv;
			xa = (xa << 11) | (xa >>> (32 - 11));
			xu = xb + xu;
			xb = (xb << 11) | (xb >>> (32 - 11));
			x0 ^= xh;
			x1 ^= xg;
			x2 ^= xj;
			x3 ^= xi;
			x4 ^= xl;
			x5 ^= xk;
			x6 ^= xn;
			x7 ^= xm;
			x8 ^= xp;
			x9 ^= xo;
			xa ^= xr;
			xb ^= xq;
			xc ^= xt;
			xd ^= xs;
			xe ^= xv;
			xf ^= xu;
		}
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
	private static final void encodeLEInt(int val, byte[] buf, int off)
	{
		buf[off + 0] = (byte)val;
		buf[off + 1] = (byte)(val >>> 8);
		buf[off + 2] = (byte)(val >>> 16);
		buf[off + 3] = (byte)(val >>> 24);
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
		return (buf[off + 0] & 0xFF)
			| ((buf[off + 1] & 0xFF) << 8)
			| ((buf[off + 2] & 0xFF) << 16)
			| ((buf[off + 3] & 0xFF) << 24);
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		doReset();
	}

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		inputBlock(data);
		sixteenRounds();
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] out, int off)
	{
		int ptr = flush();
		byte[] buf = getBlockBuffer();
		buf[ptr ++] = (byte)0x80;
		while (ptr < 32)
			buf[ptr ++] = 0x00;
		inputBlock(buf);
		sixteenRounds();
		xv ^= 1;
		for (int j = 0; j < 10; j ++)
			sixteenRounds();
		int dlen = getDigestLength();
		encodeLEInt(x0, out, off +  0);
		encodeLEInt(x1, out, off +  4);
		encodeLEInt(x2, out, off +  8);
		encodeLEInt(x3, out, off + 12);
		encodeLEInt(x4, out, off + 16);
		encodeLEInt(x5, out, off + 20);
		encodeLEInt(x6, out, off + 24);
		if (dlen == 28)
			return;
		encodeLEInt(x7, out, off + 28);
		if (dlen == 32)
			return;
		encodeLEInt(x8, out, off + 32);
		encodeLEInt(x9, out, off + 36);
		encodeLEInt(xa, out, off + 40);
		encodeLEInt(xb, out, off + 44);
		if (dlen == 48)
			return;
		encodeLEInt(xc, out, off + 48);
		encodeLEInt(xd, out, off + 52);
		encodeLEInt(xe, out, off + 56);
		encodeLEInt(xf, out, off + 60);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		doReset();
	}

	/**
	 * Get the initial values.
	 *
	 * @return  the IV
	 */
	abstract int[] getIV();

	/** @see DigestEngine */
	public int getInternalBlockLength()
	{
		return 32;
	}

	/** @see Digest */
	public int getBlockLength()
	{
		/*
		 * From the CubeHash specification:
		 *
		 * << Applications such as HMAC that pad to a full block
		 *    of SHA-h input are required to pad to a full minimal
		 *    integral number of b-byte blocks for CubeHashr/b-h. >>
		 *
		 * Here, b = 32.
		 */
		return -32;
	}

	private final void doReset()
	{
		int[] iv = getIV();
		x0 = iv[ 0];
		x1 = iv[ 1];
		x2 = iv[ 2];
		x3 = iv[ 3];
		x4 = iv[ 4];
		x5 = iv[ 5];
		x6 = iv[ 6];
		x7 = iv[ 7];
		x8 = iv[ 8];
		x9 = iv[ 9];
		xa = iv[10];
		xb = iv[11];
		xc = iv[12];
		xd = iv[13];
		xe = iv[14];
		xf = iv[15];
		xg = iv[16];
		xh = iv[17];
		xi = iv[18];
		xj = iv[19];
		xk = iv[20];
		xl = iv[21];
		xm = iv[22];
		xn = iv[23];
		xo = iv[24];
		xp = iv[25];
		xq = iv[26];
		xr = iv[27];
		xs = iv[28];
		xt = iv[29];
		xu = iv[30];
		xv = iv[31];
	}

	/** @see DigestEngine */
	protected Digest copyState(CubeHashCore dst)
	{
		dst.x0 = x0;
		dst.x1 = x1;
		dst.x2 = x2;
		dst.x3 = x3;
		dst.x4 = x4;
		dst.x5 = x5;
		dst.x6 = x6;
		dst.x7 = x7;
		dst.x8 = x8;
		dst.x9 = x9;
		dst.xa = xa;
		dst.xb = xb;
		dst.xc = xc;
		dst.xd = xd;
		dst.xe = xe;
		dst.xf = xf;
		dst.xg = xg;
		dst.xh = xh;
		dst.xi = xi;
		dst.xj = xj;
		dst.xk = xk;
		dst.xl = xl;
		dst.xm = xm;
		dst.xn = xn;
		dst.xo = xo;
		dst.xp = xp;
		dst.xq = xq;
		dst.xr = xr;
		dst.xs = xs;
		dst.xt = xt;
		dst.xu = xu;
		dst.xv = xv;
		return super.copyState(dst);
	}

	/** @see Digest */
	public String toString()
	{
		return "CubeHash-" + (getDigestLength() << 3);
	}
}
