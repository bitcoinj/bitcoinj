// $Id: Skein224.java 253 2011-06-07 18:33:10Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the Skein-224 digest algorithm under the
 * {@link Digest} API. In the Skein specification, that function is
 * called under the full name "Skein-512-224".</p>
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
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class Skein224 extends SkeinBigCore {

	/**
	 * Create the engine.
	 */
	public Skein224()
	{
		super();
	}

	/** The initial value for Skein-224. */
	private static final long[] initVal = {
		0xCCD0616248677224L, 0xCBA65CF3A92339EFL,
		0x8CCD69D652FF4B64L, 0x398AED7B3AB890B4L,
		0x0F59D1B1457D2BD0L, 0x6776FE6575D4EB3DL,
		0x99FBC70E997413E9L, 0x9E2CFCCFE1C41EF7L
	};

	/** @see SkeinBigCore */
	long[] getInitVal()
	{
		return initVal;
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 28;
	}

	/** @see SkeinBigCore */
	SkeinBigCore dup()
	{
		return new Skein224();
	}
}
