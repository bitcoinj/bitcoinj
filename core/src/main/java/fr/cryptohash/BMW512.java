// $Id: BMW512.java 166 2010-05-03 16:44:36Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the BMW-512 ("Blue Midnight Wish") digest
 * algorithm under the {@link Digest} API.</p>
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
 * @version   $Revision: 166 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class BMW512 extends BMWBigCore {

	/**
	 * Create the engine.
	 */
	public BMW512()
	{
		super();
	}

	/** The initial value for BMW-512. */
	private static final long[] initVal = {
		0x8081828384858687L, 0x88898A8B8C8D8E8FL,
		0x9091929394959697L, 0x98999A9B9C9D9E9FL,
		0xA0A1A2A3A4A5A6A7L, 0xA8A9AAABACADAEAFL,
		0xB0B1B2B3B4B5B6B7L, 0xB8B9BABBBCBDBEBFL,
		0xC0C1C2C3C4C5C6C7L, 0xC8C9CACBCCCDCECFL,
		0xD0D1D2D3D4D5D6D7L, 0xD8D9DADBDCDDDEDFL,
		0xE0E1E2E3E4E5E6E7L, 0xE8E9EAEBECEDEEEFL,
		0xF0F1F2F3F4F5F6F7L, 0xF8F9FAFBFCFDFEFFL
	};

	/** @see BMWSmallCore */
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
		return copyState(new BMW512());
	}
}
