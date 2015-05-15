// $Id: Hamsi224.java 236 2010-06-18 15:41:41Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the Hamsi-224 digest algorithm under the
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
 * @version   $Revision: 236 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class Hamsi224 extends HamsiSmallCore {

	/**
	 * Create the engine.
	 */
	public Hamsi224()
	{
		super();
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 28;
	}

	private static final int[] IV = {
		0xc3967a67, 0xc3bc6c20, 0x4bc3bcc3, 0xa7c3bc6b,
		0x2c204b61, 0x74686f6c, 0x69656b65, 0x20556e69
	};

	/*
	 * Wrong IV, but compatible with test vectors submitted for
	 * round 2 of the SHA-3 competition.
	private static final int[] IV = {
		0x3c967a67, 0x3cbc6c20, 0xb4c343c3, 0xa73cbc6b,
		0x2c204b61, 0x74686f6c, 0x69656b65, 0x20556e69
	};
	 */

	/** @see HamsiSmallCore */
	int[] getIV()
	{
		return IV;
	}

	/** @see HamsiSmallCore */
	HamsiSmallCore dup()
	{
		return new Hamsi224();
	}
}
