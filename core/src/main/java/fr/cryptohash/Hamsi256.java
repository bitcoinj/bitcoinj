// $Id: Hamsi256.java 206 2010-06-01 18:18:57Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the Hamsi-256 digest algorithm under the
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

public class Hamsi256 extends HamsiSmallCore {

	/**
	 * Create the engine.
	 */
	public Hamsi256()
	{
		super();
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 32;
	}

	private static final int[] IV = {
		0x76657273, 0x69746569, 0x74204c65, 0x7576656e,
		0x2c204465, 0x70617274, 0x656d656e, 0x7420456c
	};

	/** @see HamsiSmallCore */
	int[] getIV()
	{
		return IV;
	}

	/** @see HamsiSmallCore */
	HamsiSmallCore dup()
	{
		return new Hamsi256();
	}
}
