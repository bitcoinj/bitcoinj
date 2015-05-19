// $Id: SIMD256.java 156 2010-04-26 17:55:11Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the SIMD-256 digest algorithm under the
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
 * @version   $Revision: 156 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class SIMD256 extends SIMDSmallCore {

	/**
	 * Create the engine.
	 */
	public SIMD256()
	{
		super();
	}

	/** The initial value for SIMD-256. */
	private static final int[] initVal = {
		0x4D567983, 0x07190BA9, 0x8474577B, 0x39D726E9,
		0xAAF3D925, 0x3EE20B03, 0xAFD5E751, 0xC96006D3,
		0xC2C2BA14, 0x49B3BCB4, 0xF67CAF46, 0x668626C9,
		0xE2EAA8D2, 0x1FF47833, 0xD0C661A5, 0x55693DE1
	};

	/** @see SIMDSmallCore */
	int[] getInitVal()
	{
		return initVal;
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 32;
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new SIMD256());
	}
}
