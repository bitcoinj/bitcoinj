// $Id: SIMD512.java 156 2010-04-26 17:55:11Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the SIMD-512 digest algorithm under the
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

public class SIMD512 extends SIMDBigCore {

	/**
	 * Create the engine.
	 */
	public SIMD512()
	{
		super();
	}

	/** The initial value for SIMD-512. */
	private static final int[] initVal = {
		0x0BA16B95, 0x72F999AD, 0x9FECC2AE, 0xBA3264FC,
		0x5E894929, 0x8E9F30E5, 0x2F1DAA37, 0xF0F2C558,
		0xAC506643, 0xA90635A5, 0xE25B878B, 0xAAB7878F,
		0x88817F7A, 0x0A02892B, 0x559A7550, 0x598F657E,
		0x7EEF60A1, 0x6B70E3E8, 0x9C1714D1, 0xB958E2A8,
		0xAB02675E, 0xED1C014F, 0xCD8D65BB, 0xFDB7A257,
		0x09254899, 0xD699C7BC, 0x9019B6DC, 0x2B9022E4,
		0x8FA14956, 0x21BF9BD3, 0xB94D0943, 0x6FFDDC22
	};

	/** @see SIMDSmallCore */
	int[] getInitVal()
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
		return copyState(new SIMD512());
	}
}
