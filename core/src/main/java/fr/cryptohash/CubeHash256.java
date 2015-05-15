// $Id: CubeHash256.java 183 2010-05-08 21:34:53Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the CubeHash-256 digest algorithm under the
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
 * @version   $Revision: 183 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class CubeHash256 extends CubeHashCore {

	private static final int[] IV = {
		0xEA2BD4B4, 0xCCD6F29F, 0x63117E71,
		0x35481EAE, 0x22512D5B, 0xE5D94E63,
		0x7E624131, 0xF4CC12BE, 0xC2D0B696,
		0x42AF2070, 0xD0720C35, 0x3361DA8C,
		0x28CCECA4, 0x8EF8AD83, 0x4680AC00,
		0x40E5FBAB, 0xD89041C3, 0x6107FBD5,
		0x6C859D41, 0xF0B26679, 0x09392549,
		0x5FA25603, 0x65C892FD, 0x93CB6285,
		0x2AF2B5AE, 0x9E4B4E60, 0x774ABFDD,
		0x85254725, 0x15815AEB, 0x4AB6AAD6,
		0x9CDAF8AF, 0xD6032C0A
	};

	/**
	 * Create the engine.
	 */
	public CubeHash256()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new CubeHash256());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 32;
	}

	/** @see CubeHashCore */
	int[] getIV()
	{
		return IV;
	}
}
