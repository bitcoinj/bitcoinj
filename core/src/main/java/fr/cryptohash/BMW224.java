// $Id: BMW224.java 166 2010-05-03 16:44:36Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the BMW-224 ("Blue Midnight Wish") digest
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

public class BMW224 extends BMWSmallCore {

	/**
	 * Create the engine.
	 */
	public BMW224()
	{
		super();
	}

	/** The initial value for BMW-224. */
	private static final int[] initVal = {
		0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F,
		0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F,
		0x20212223, 0x24252627, 0x28292A2B, 0x2C2D2E2F,
		0x30313233, 0x34353637, 0x38393A3B, 0x3C3D3E3F
	};

	/** @see BMWSmallCore */
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
		return copyState(new BMW224());
	}
}
