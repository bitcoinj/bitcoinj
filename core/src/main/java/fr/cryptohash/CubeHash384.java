// $Id: CubeHash384.java 183 2010-05-08 21:34:53Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the CubeHash-384 digest algorithm under the
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
 * @version   $Revision: 183 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class CubeHash384 extends CubeHashCore {

	private static final int[] IV = {
		0xE623087E, 0x04C00C87, 0x5EF46453,
		0x69524B13, 0x1A05C7A9, 0x3528DF88,
		0x6BDD01B5, 0x5057B792, 0x6AA7A922,
		0x649C7EEE, 0xF426309F, 0xCB629052,
		0xFC8E20ED, 0xB3482BAB, 0xF89E5E7E,
		0xD83D4DE4, 0x44BFC10D, 0x5FC1E63D,
		0x2104E6CB, 0x17958F7F, 0xDBEAEF70,
		0xB4B97E1E, 0x32C195F6, 0x6184A8E4,
		0x796C2543, 0x23DE176D, 0xD33BBAEC,
		0x0C12E5D2, 0x4EB95A7B, 0x2D18BA01,
		0x04EE475F, 0x1FC5F22E
	};

	/**
	 * Create the engine.
	 */
	public CubeHash384()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new CubeHash384());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 48;
	}

	/** @see CubeHashCore */
	int[] getIV()
	{
		return IV;
	}
}
