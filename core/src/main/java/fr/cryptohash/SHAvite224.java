// $Id: SHAvite224.java 222 2010-06-09 10:47:13Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the SHAvite-224 digest algorithm under the
 * {@link Digest} API (in the SHAvite-3 specification, this function
 * is known as "SHAvite-3 with a 224-bit output").</p>
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
 * @version   $Revision: 222 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class SHAvite224 extends SHAviteSmallCore {

	/**
	 * Create the engine.
	 */
	public SHAvite224()
	{
		super();
	}

	/** The initial value for SHAvite-224. */
	private static final int[] initVal = {
		0x6774F31C, 0x990AE210, 0xC87D4274, 0xC9546371,
		0x62B2AEA8, 0x4B5801D8, 0x1B702860, 0x842F3017
	};

	/** @see SHAviteSmallCore */
	int[] getInitVal()
	{
		return initVal;
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 28;
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new SHAvite224());
	}
}
