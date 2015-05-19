// $Id: Fugue224.java 159 2010-05-01 15:41:17Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the Fugue-224 digest algorithm under the
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
 * @version   $Revision: 159 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class Fugue224 extends Fugue2Core {

	/**
	 * Create the engine.
	 */
	public Fugue224()
	{
		super();
	}

	/** The initial value for Fugue-224. */
	private static final int[] initVal = {
		0xf4c9120d, 0x6286f757, 0xee39e01c, 0xe074e3cb,
		0xa1127c62, 0x9a43d215, 0xbd8d679a
	};

	/** @see FugueCore */
	int[] getIV()
	{
		return initVal;
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 28;
	}

	/** @see FugueCore */
	FugueCore dup()
	{
		return new Fugue224();
	}
}
