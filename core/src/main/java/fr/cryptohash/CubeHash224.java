// $Id: CubeHash224.java 183 2010-05-08 21:34:53Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the CubeHash-224 digest algorithm under the
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

public class CubeHash224 extends CubeHashCore {

	private static final int[] IV = {
		0xB0FC8217, 0x1BEE1A90, 0x829E1A22,
		0x6362C342, 0x24D91C30, 0x03A7AA24,
		0xA63721C8, 0x85B0E2EF, 0xF35D13F3,
		0x41DA807D, 0x21A70CA6, 0x1F4E9774,
		0xB3E1C932, 0xEB0A79A8, 0xCDDAAA66,
		0xE2F6ECAA, 0x0A713362, 0xAA3080E0,
		0xD8F23A32, 0xCEF15E28, 0xDB086314,
		0x7F709DF7, 0xACD228A4, 0x704D6ECE,
		0xAA3EC95F, 0xE387C214, 0x3A6445FF,
		0x9CAB81C3, 0xC73D4B98, 0xD277AEBE,
		0xFD20151C, 0x00CB573E
	};

	/**
	 * Create the engine.
	 */
	public CubeHash224()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new CubeHash224());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 28;
	}

	/** @see CubeHashCore */
	int[] getIV()
	{
		return IV;
	}
}
