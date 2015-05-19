// $Id: SIMD384.java 156 2010-04-26 17:55:11Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the SIMD-384 digest algorithm under the
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

public class SIMD384 extends SIMDBigCore {

	/**
	 * Create the engine.
	 */
	public SIMD384()
	{
		super();
	}

	/** The initial value for SIMD-384. */
	private static final int[] initVal = {
		0x8A36EEBC, 0x94A3BD90, 0xD1537B83, 0xB25B070B,
		0xF463F1B5, 0xB6F81E20, 0x0055C339, 0xB4D144D1,
		0x7360CA61, 0x18361A03, 0x17DCB4B9, 0x3414C45A,
		0xA699A9D2, 0xE39E9664, 0x468BFE77, 0x51D062F8,
		0xB9E3BFE8, 0x63BECE2A, 0x8FE506B9, 0xF8CC4AC2,
		0x7AE11542, 0xB1AADDA1, 0x64B06794, 0x28D2F462,
		0xE64071EC, 0x1DEB91A8, 0x8AC8DB23, 0x3F782AB5,
		0x039B5CB8, 0x71DDD962, 0xFADE2CEA, 0x1416DF71
	};

	/** @see SIMDSmallCore */
	int[] getInitVal()
	{
		return initVal;
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 48;
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new SIMD384());
	}
}
