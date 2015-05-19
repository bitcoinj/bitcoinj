// $Id: BLAKE512.java 252 2011-06-07 17:55:14Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the BLAKE-512 digest algorithm under the
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
 * @version   $Revision: 252 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class BLAKE512 extends BLAKEBigCore {

	/**
	 * Create the engine.
	 */
	public BLAKE512()
	{
		super();
	}

	/** The initial value for BLAKE-512. */
	private static final long[] initVal = {
		0x6A09E667F3BCC908L, 0xBB67AE8584CAA73BL,
		0x3C6EF372FE94F82BL, 0xA54FF53A5F1D36F1L,
		0x510E527FADE682D1L, 0x9B05688C2B3E6C1FL,
		0x1F83D9ABFB41BD6BL, 0x5BE0CD19137E2179L
	};

	/** @see BLAKESmallCore */
	long[] getInitVal()
	{
		return initVal;
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 64;
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new BLAKE512());
	}
}
