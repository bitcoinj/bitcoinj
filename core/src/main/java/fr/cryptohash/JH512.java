// $Id: JH512.java 255 2011-06-07 19:50:20Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the JH-512 digest algorithm under the
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
 * @version   $Revision: 255 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class JH512 extends JHCore {

	private static final long[] IV = {
		0x6fd14b963e00aa17L, 0x636a2e057a15d543L,
		0x8a225e8d0c97ef0bL, 0xe9341259f2b3c361L,
		0x891da0c1536f801eL, 0x2aa9056bea2b6d80L,
		0x588eccdb2075baa6L, 0xa90f3a76baf83bf7L,
		0x0169e60541e34a69L, 0x46b58a8e2e6fe65aL,
		0x1047a7d0c1843c24L, 0x3b6e71b12d5ac199L,
		0xcf57f6ec9db1f856L, 0xa706887c5716b156L,
		0xe3c2fcdfe68517fbL, 0x545a4678cc8cdd4bL
	};

	/**
	 * Create the engine.
	 */
	public JH512()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new JH512());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 64;
	}

	/** @see JHCore */
	long[] getIV()
	{
		return IV;
	}
}
