// $Id: MDHelper.java 157 2010-04-26 19:03:44Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the padding common to MD4, MD5, the SHA family,
 * and RIPEMD-160. This code works as long as the internal block length
 * is a power of 2, which is the case for all these algorithms.</p>
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
 * @version   $Revision: 157 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

abstract class MDHelper extends DigestEngine {

	/**
	 * Create the object. Little-endian padding is for MD4, MD5 and
	 * RIPEMD-160; the SHA family uses big-endian padding. The
	 * MD padding includes an encoding of the input message bit length,
	 * which is over 64 bits for some algorithms, 128-bit for others
	 * (namely SHA-384 and SHA-512). Note that this implementation
	 * handles only message lengths which fit on 64 bits.
	 *
	 * @param littleEndian   {@code true} for little-endian padding
	 * @param lenlen         the length encoding length, in bytes (must
	 *                       be at least 8)
	 */
	MDHelper(boolean littleEndian, int lenlen)
	{
		this(littleEndian, lenlen, (byte)0x80);
	}

	/**
	 * Create the object. Little-endian padding is for MD4, MD5 and
	 * RIPEMD-160; the SHA family uses big-endian padding. The
	 * MD padding includes an encoding of the input message bit length,
	 * which is over 64 bits for some algorithms, 128-bit for others
	 * (namely SHA-384 and SHA-512). Note that this implementation
	 * handles only message lengths which fit on 64 bits. The first
	 * additional byte value is specified; this is normally 0x80,
	 * except for Tiger (not Tiger2) which uses 0x01.
	 *
	 * @param littleEndian   {@code true} for little-endian padding
	 * @param lenlen         the length encoding length, in bytes (must
	 *                       be at least 8)
	 * @param fbyte          the first padding byte
	 */
	MDHelper(boolean littleEndian, int lenlen, byte fbyte)
	{
		this.littleEndian = littleEndian;
		countBuf = new byte[lenlen];
		this.fbyte = fbyte;
	}

	private boolean littleEndian;
	private byte[] countBuf;
	private byte fbyte;

	/**
	 * Compute the padding. The padding data is input into the engine,
	 * which is flushed.
	 */
	protected void makeMDPadding()
	{
		int dataLen = flush();
		int blen = getBlockLength();
		long currentLength = getBlockCount() * (long)blen;
		currentLength = (currentLength + (long)dataLen) * 8L;
		int lenlen = countBuf.length;
		if (littleEndian) {
			encodeLEInt((int)currentLength, countBuf, 0);
			encodeLEInt((int)(currentLength >>> 32), countBuf, 4);
		} else {
			encodeBEInt((int)(currentLength >>> 32),
				countBuf, lenlen - 8);
			encodeBEInt((int)currentLength,
				countBuf, lenlen - 4);
		}
		int endLen = (dataLen + lenlen + blen) & ~(blen - 1);
		update(fbyte);
		for (int i = dataLen + 1; i < endLen - lenlen; i ++)
			update((byte)0);
		update(countBuf);

		/*
		 * This code is used only for debugging purposes.
		 *
		if (flush() != 0)
			throw new Error("panic: buffering went astray");
		 *
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
	private static final void encodeLEInt(int val, byte[] buf, int off)
	{
		buf[off + 0] = (byte)val;
		buf[off + 1] = (byte)(val >>> 8);
		buf[off + 2] = (byte)(val >>> 16);
		buf[off + 3] = (byte)(val >>> 24);
	}

	/**
	 * Encode the 32-bit word {@code val} into the array
	 * {@code buf} at offset {@code off}, in big-endian
	 * convention (most significant byte first).
	 *
	 * @param val   the value to encode
	 * @param buf   the destination buffer
	 * @param off   the destination offset
	 */
	private static final void encodeBEInt(int val, byte[] buf, int off)
	{
		buf[off + 0] = (byte)(val >>> 24);
		buf[off + 1] = (byte)(val >>> 16);
		buf[off + 2] = (byte)(val >>> 8);
		buf[off + 3] = (byte)val;
	}
}
