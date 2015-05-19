// $Id: JH384.java 255 2011-06-07 19:50:20Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the JH-384 digest algorithm under the
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

public class JH384 extends JHCore {

	private static final long[] IV = {
		0x481e3bc6d813398aL, 0x6d3b5e894ade879bL,
		0x63faea68d480ad2eL, 0x332ccb21480f8267L,
		0x98aec84d9082b928L, 0xd455ea3041114249L,
		0x36f555b2924847ecL, 0xc7250a93baf43ce1L,
		0x569b7f8a27db454cL, 0x9efcbd496397af0eL,
		0x589fc27d26aa80cdL, 0x80c08b8c9deb2edaL,
		0x8a7981e8f8d5373aL, 0xf43967adddd17a71L,
		0xa9b4d3bda475d394L, 0x976c3fba9842737fL
	};

	/**
	 * Create the engine.
	 */
	public JH384()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new JH384());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 48;
	}

	/** @see JHCore */
	long[] getIV()
	{
		return IV;
	}
}
