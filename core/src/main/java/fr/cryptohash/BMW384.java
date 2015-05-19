// $Id: BMW384.java 166 2010-05-03 16:44:36Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the BMW-384 ("Blue Midnight Wish") digest
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

public class BMW384 extends BMWBigCore {

	/**
	 * Create the engine.
	 */
	public BMW384()
	{
		super();
	}

	/** The initial value for BMW-384. */
	private static final long[] initVal = {
		0x0001020304050607L, 0x08090A0B0C0D0E0FL,
		0x1011121314151617L, 0x18191A1B1C1D1E1FL,
		0x2021222324252627L, 0x28292A2B2C2D2E2FL,
		0x3031323334353637L, 0x38393A3B3C3D3E3FL,
		0x4041424344454647L, 0x48494A4B4C4D4E4FL,
		0x5051525354555657L, 0x58595A5B5C5D5E5FL,
		0x6061626364656667L, 0x68696A6B6C6D6E6FL,
		0x7071727374757677L, 0x78797A7B7C7D7E7FL
	};

	/** @see BMWSmallCore */
	long[] getInitVal()
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
		return copyState(new BMW384());
	}
}
