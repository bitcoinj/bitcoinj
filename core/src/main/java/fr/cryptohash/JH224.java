// $Id: JH224.java 255 2011-06-07 19:50:20Z tp $

package fr.cryptohash;

/**
 * <p>This class implements the JH-224 digest algorithm under the
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
 * @version   $Revision: 255 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */

public class JH224 extends JHCore {

	private static final long[] IV = {
		0x2dfedd62f99a98acL, 0xae7cacd619d634e7L,
		0xa4831005bc301216L, 0xb86038c6c9661494L,
		0x66d9899f2580706fL, 0xce9ea31b1d9b1adcL,
		0x11e8325f7b366e10L, 0xf994857f02fa06c1L,
		0x1b4f1b5cd8c840b3L, 0x97f6a17f6e738099L,
		0xdcdf93a5adeaa3d3L, 0xa431e8dec9539a68L,
		0x22b4a98aec86a1e4L, 0xd574ac959ce56cf0L,
		0x15960deab5ab2bbfL, 0x9611dcf0dd64ea6eL
	};

	/**
	 * Create the engine.
	 */
	public JH224()
	{
	}

	/** @see Digest */
	public Digest copy()
	{
		return copyState(new JH224());
	}

	/** @see Digest */
	public int getDigestLength()
	{
		return 28;
	}

	/** @see JHCore */
	long[] getIV()
	{
		return IV;
	}
}
