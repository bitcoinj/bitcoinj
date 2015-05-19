// $Id: HMAC.java 214 2010-06-03 17:25:08Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the HMAC message authentication algorithm,
 * under the {@link Digest} API, using the {@link DigestEngine} class.
 * HMAC is defined in RFC 2104 (also FIPS 198a). This implementation
 * uses an underlying digest algorithm, provided as parameter to the
 * constructor.</p>
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

public class HMAC extends DigestEngine {

	/**
	 * Build the object. The provided digest algorithm will be used
	 * internally; it MUST NOT be directly accessed afterwards. The
	 * {@code key} array holds the MAC key; the key is copied
	 * internally, which means that the caller may modify the {@code
	 * key} array afterwards.
	 *
	 * @param dig   the underlying hash function
	 * @param key   the MAC key
	 */
	public HMAC(Digest dig, byte[] key)
	{
		dig.reset();
		this.dig = dig;
		int B = dig.getBlockLength();
		if (B < 0) {
			/*
			 * Virtual block length: inferred from the key
			 * length, with rounding (used for Fugue-xxx).
			 */
			int n = -B;
			B = n * ((key.length + (n - 1)) / n);
		}
		byte[] keyB = new byte[B];
		int len = key.length;
		if (len > B) {
			key = dig.digest(key);
			len = key.length;
			if (len > B)
				len = B;
		}
		System.arraycopy(key, 0, keyB, 0, len);
		/*
		 * Newly created arrays are guaranteed filled with zeroes,
		 * hence the key padding is already done.
		 */
		processKey(keyB);

		outputLength = -1;
		tmpOut = new byte[dig.getDigestLength()];
		reset();
	}

	/**
	 * Build the object. The provided digest algorithm will be used
	 * internally; it MUST NOT be directly accessed afterwards. The
	 * {@code key} array holds the MAC key; the key is copied
	 * internally, which means that the caller may modify the
	 * {@code key} array afterwards. The provided output length
	 * is the maximum HMAC output length, in bytes: the digest
	 * output will be truncated, if needed, to respect that limit.
	 *
	 * @param dig            the underlying hash function
	 * @param key            the MAC key
	 * @param outputLength   the HMAC output length (in bytes)
	 */
	public HMAC(Digest dig, byte[] key, int outputLength)
	{
		this(dig, key);
		if (outputLength < dig.getDigestLength())
			this.outputLength = outputLength;
	}

	/**
	 * Internal constructor, used for cloning. The key is referenced,
	 * not copied.
	 *
	 * @param dig            the digest
	 * @param kipad          the (internal) ipad key
	 * @param kopad          the (internal) opad key
	 * @param outputLength   the output length, or -1
	 */
	private HMAC(Digest dig, byte[] kipad, byte[] kopad, int outputLength)
	{
		this.dig = dig;
		this.kipad = kipad;
		this.kopad = kopad;
		this.outputLength = outputLength;
		tmpOut = new byte[dig.getDigestLength()];
	}

	private Digest dig;
	private byte[] kipad, kopad;
	private int outputLength;
	private byte[] tmpOut;

	private void processKey(byte[] keyB)
	{
		int B = keyB.length;
		kipad = new byte[B];
		kopad = new byte[B];
		for (int i = 0; i < B; i ++) {
			int x = keyB[i];
			kipad[i] = (byte)(x ^ 0x36);
			kopad[i] = (byte)(x ^ 0x5C);
		}
	}

	/** @see Digest */
	public Digest copy()
	{
		HMAC h = new HMAC(dig.copy(), kipad, kopad, outputLength);
		return copyState(h);
	}

	/** @see Digest */
	public int getDigestLength()
	{
		/*
		 * At construction time, outputLength is first set to 0,
		 * which means that this method will return 0, which is
		 * appropriate since at that time "dig" has not yet been
		 * set.
		 */
		return outputLength < 0 ? dig.getDigestLength() : outputLength;
	}

	/** @see Digest */
	public int getBlockLength()
	{
		/*
		 * Internal block length is not defined for HMAC, which
		 * is not, stricto-sensu, an iterated hash function.
		 * The value 64 should provide correct buffering. Do NOT
		 * change this value without checking doPadding().
		 */
		return 64;
	}

	/** @see DigestEngine */
	protected void engineReset()
	{
		dig.reset();
		dig.update(kipad);
	}

	private int onlyThis = 0;
	private static final byte[] zeroPad = new byte[64];

	/** @see DigestEngine */
	protected void processBlock(byte[] data)
	{
		if (onlyThis > 0) {
			dig.update(data, 0, onlyThis);
			onlyThis = 0;
		} else {
			dig.update(data);
		}
	}

	/** @see DigestEngine */
	protected void doPadding(byte[] output, int outputOffset)
	{
		/*
		 * This is slightly ugly... we need to get the still
		 * buffered data, but the only way to get it from
		 * DigestEngine is to input some more bytes and wait
		 * for the processBlock() call. We set a variable
		 * with the count of actual data bytes, so that
		 * processBlock() knows what to do.
		 */
		onlyThis = flush();
		if (onlyThis > 0)
			update(zeroPad, 0, 64 - onlyThis);

		int olen = tmpOut.length;
		dig.digest(tmpOut, 0, olen);
		dig.update(kopad);
		dig.update(tmpOut);
		dig.digest(tmpOut, 0, olen);
		if (outputLength >= 0)
			olen = outputLength;
		System.arraycopy(tmpOut, 0, output, outputOffset, olen);
	}

	/** @see DigestEngine */
	protected void doInit()
	{
		/*
		 * Empty: we do not want to do anything here because
		 * it would prevent correct cloning. The initialization
		 * job is done in the constructor.
		 */
	}

	/** @see Digest */
	public String toString()
	{
		return "HMAC/" + dig.toString();
	}
}
