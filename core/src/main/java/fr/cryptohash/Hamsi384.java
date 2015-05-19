// $Id: Hamsi384.java 206 2010-06-01 18:18:57Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the Hamsi-384 digest algorithm under the
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
 * @version   $Revision: 206 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class Hamsi384 extends HamsiBigCore {

	/**
	 * Create the engine.
	 */
	public Hamsi384()
	{
		super();
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 48;
	}

	private static final int[] IV = {
		0x656b7472, 0x6f746563, 0x686e6965, 0x6b2c2043,
		0x6f6d7075, 0x74657220, 0x53656375, 0x72697479,
		0x20616e64, 0x20496e64, 0x75737472, 0x69616c20,
		0x43727970, 0x746f6772, 0x61706879, 0x2c204b61
	};

	/** @see HamsiBigCore */
	int[] getIV()
	{
		return IV;
	}

	/** @see HamsiBigCore */
	HamsiBigCore dup()
	{
		return new Hamsi384();
	}
}
