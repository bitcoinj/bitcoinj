// $Id: Hamsi512.java 206 2010-06-01 18:18:57Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the Hamsi-512 digest algorithm under the
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

public class Hamsi512 extends HamsiBigCore {

	/**
	 * Create the engine.
	 */
	public Hamsi512()
	{
		super();
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 64;
	}

	private static final int[] IV = {
		0x73746565, 0x6c706172, 0x6b204172, 0x656e6265,
		0x72672031, 0x302c2062, 0x75732032, 0x3434362c,
		0x20422d33, 0x30303120, 0x4c657576, 0x656e2d48,
		0x65766572, 0x6c65652c, 0x2042656c, 0x6769756d
	};

	/** @see HamsiBigCore */
	int[] getIV()
	{
		return IV;
	}

	/** @see HamsiBigCore */
	HamsiBigCore dup()
	{
		return new Hamsi512();
	}
}
