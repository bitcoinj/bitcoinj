// $Id: CubeHash512.java 183 2010-05-08 21:34:53Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the CubeHash-512 digest algorithm under the
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

public class CubeHash512 extends CubeHashCore {

	private static final int[] IV = {
		0x2AEA2A61, 0x50F494D4, 0x2D538B8B,
		0x4167D83E, 0x3FEE2313, 0xC701CF8C,
		0xCC39968E, 0x50AC5695, 0x4D42C787,
		0xA647A8B3, 0x97CF0BEF, 0x825B4537,
		0xEEF864D2, 0xF22090C4, 0xD0E5CD33,
		0xA23911AE, 0xFCD398D9, 0x148FE485,
		0x1B017BEF, 0xB6444532, 0x6A536159,
		0x2FF5781C, 0x91FA7934, 0x0DBADEA9,
		0xD65C8A2B, 0xA5A70E75, 0xB1C62456,
		0xBC796576, 0x1921C8F7, 0xE7989AF1,
		0x7795D246, 0xD43E3B44
	};

	/**
	 * Create the engine.
	 */
	public CubeHash512()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new CubeHash512());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 64;
	}

	/** @see CubeHashCore */
	int[] getIV()
	{
		return IV;
	}
}
