// $Id: Fugue2Core.java 159 2010-05-01 15:41:17Z tp $

package fr.cryptohash;

/**
 * This class is the base class for Fugue-224 and Fugue-256.
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

abstract class Fugue2Core extends FugueCore {

	/** @see FugueCore */
	void process(int w, byte[] buf, int off, int num)
	{
		int[] S = this.S;
		switch (rshift) {
		case 1:
			S[ 4] ^= S[24];
			S[24] = w;
			S[ 2] ^= S[24];
			S[25] ^= S[18];
			S[21] ^= S[25];
			S[22] ^= S[26];
			S[23] ^= S[27];
			S[ 6] ^= S[25];
			S[ 7] ^= S[26];
			S[ 8] ^= S[27];
			smix(21, 22, 23, 24);
			S[18] ^= S[22];
			S[19] ^= S[23];
			S[20] ^= S[24];
			S[ 3] ^= S[22];
			S[ 4] ^= S[23];
			S[ 5] ^= S[24];
			smix(18, 19, 20, 21);
			if (num -- <= 0) {
				rshift = 2;
				return;
			}
			w = (buf[off] << 24)
				| ((buf[off + 1] & 0xFF) << 16)
				| ((buf[off + 2] & 0xFF) << 8)
				| (buf[off + 3] & 0xFF);
			off += 4;
			/* fall through */
		case 2:
			S[28] ^= S[18];
			S[18] = w;
			S[26] ^= S[18];
			S[19] ^= S[12];
			S[15] ^= S[19];
			S[16] ^= S[20];
			S[17] ^= S[21];
			S[ 0] ^= S[19];
			S[ 1] ^= S[20];
			S[ 2] ^= S[21];
			smix(15, 16, 17, 18);
			S[12] ^= S[16];
			S[13] ^= S[17];
			S[14] ^= S[18];
			S[27] ^= S[16];
			S[28] ^= S[17];
			S[29] ^= S[18];
			smix(12, 13, 14, 15);
			if (num -- <= 0) {
				rshift = 3;
				return;
			}
			w = (buf[off] << 24)
				| ((buf[off + 1] & 0xFF) << 16)
				| ((buf[off + 2] & 0xFF) << 8)
				| (buf[off + 3] & 0xFF);
			off += 4;
			/* fall through */
		case 3:
			S[22] ^= S[12];
			S[12] = w;
			S[20] ^= S[12];
			S[13] ^= S[ 6];
			S[ 9] ^= S[13];
			S[10] ^= S[14];
			S[11] ^= S[15];
			S[24] ^= S[13];
			S[25] ^= S[14];
			S[26] ^= S[15];
			smix( 9, 10, 11, 12);
			S[ 6] ^= S[10];
			S[ 7] ^= S[11];
			S[ 8] ^= S[12];
			S[21] ^= S[10];
			S[22] ^= S[11];
			S[23] ^= S[12];
			smix( 6,  7,  8,  9);
			if (num -- <= 0) {
				rshift = 4;
				return;
			}
			w = (buf[off] << 24)
				| ((buf[off + 1] & 0xFF) << 16)
				| ((buf[off + 2] & 0xFF) << 8)
				| (buf[off + 3] & 0xFF);
			off += 4;
			/* fall through */
		case 4:
			S[16] ^= S[ 6];
			S[ 6] = w;
			S[14] ^= S[ 6];
			S[ 7] ^= S[ 0];
			S[ 3] ^= S[ 7];
			S[ 4] ^= S[ 8];
			S[ 5] ^= S[ 9];
			S[18] ^= S[ 7];
			S[19] ^= S[ 8];
			S[20] ^= S[ 9];
			smix( 3,  4,  5,  6);
			S[ 0] ^= S[ 4];
			S[ 1] ^= S[ 5];
			S[ 2] ^= S[ 6];
			S[15] ^= S[ 4];
			S[16] ^= S[ 5];
			S[17] ^= S[ 6];
			smix( 0,  1,  2,  3);
			if (num -- <= 0) {
				rshift = 0;
				return;
			}
			w = (buf[off] << 24)
				| ((buf[off + 1] & 0xFF) << 16)
				| ((buf[off + 2] & 0xFF) << 8)
				| (buf[off + 3] & 0xFF);
			off += 4;
		}
		for (;;) {
			/* ================ */
			S[10] ^= S[ 0];
			S[ 0] = w;
			S[ 8] ^= S[ 0];
			S[ 1] ^= S[24];
			S[27] ^= S[ 1];
			S[28] ^= S[ 2];
			S[29] ^= S[ 3];
			S[12] ^= S[ 1];
			S[13] ^= S[ 2];
			S[14] ^= S[ 3];
			smix(27, 28, 29,  0);
			S[24] ^= S[28];
			S[25] ^= S[29];
			S[26] ^= S[ 0];
			S[ 9] ^= S[28];
			S[10] ^= S[29];
			S[11] ^= S[ 0];
			smix(24, 25, 26, 27);
			if (num -- <= 0) {
				rshift = 1;
				return;
			}
			w = (buf[off] << 24)
				| ((buf[off + 1] & 0xFF) << 16)
				| ((buf[off + 2] & 0xFF) << 8)
				| (buf[off + 3] & 0xFF);
			off += 4;
			/* ================ */
			S[ 4] ^= S[24];
			S[24] = w;
			S[ 2] ^= S[24];
			S[25] ^= S[18];
			S[21] ^= S[25];
			S[22] ^= S[26];
			S[23] ^= S[27];
			S[ 6] ^= S[25];
			S[ 7] ^= S[26];
			S[ 8] ^= S[27];
			smix(21, 22, 23, 24);
			S[18] ^= S[22];
			S[19] ^= S[23];
			S[20] ^= S[24];
			S[ 3] ^= S[22];
			S[ 4] ^= S[23];
			S[ 5] ^= S[24];
			smix(18, 19, 20, 21);
			if (num -- <= 0) {
				rshift = 2;
				return;
			}
			w = (buf[off] << 24)
				| ((buf[off + 1] & 0xFF) << 16)
				| ((buf[off + 2] & 0xFF) << 8)
				| (buf[off + 3] & 0xFF);
			off += 4;
			/* ================ */
			S[28] ^= S[18];
			S[18] = w;
			S[26] ^= S[18];
			S[19] ^= S[12];
			S[15] ^= S[19];
			S[16] ^= S[20];
			S[17] ^= S[21];
			S[ 0] ^= S[19];
			S[ 1] ^= S[20];
			S[ 2] ^= S[21];
			smix(15, 16, 17, 18);
			S[12] ^= S[16];
			S[13] ^= S[17];
			S[14] ^= S[18];
			S[27] ^= S[16];
			S[28] ^= S[17];
			S[29] ^= S[18];
			smix(12, 13, 14, 15);
			if (num -- <= 0) {
				rshift = 3;
				return;
			}
			w = (buf[off] << 24)
				| ((buf[off + 1] & 0xFF) << 16)
				| ((buf[off + 2] & 0xFF) << 8)
				| (buf[off + 3] & 0xFF);
			off += 4;
			/* ================ */
			S[22] ^= S[12];
			S[12] = w;
			S[20] ^= S[12];
			S[13] ^= S[ 6];
			S[ 9] ^= S[13];
			S[10] ^= S[14];
			S[11] ^= S[15];
			S[24] ^= S[13];
			S[25] ^= S[14];
			S[26] ^= S[15];
			smix( 9, 10, 11, 12);
			S[ 6] ^= S[10];
			S[ 7] ^= S[11];
			S[ 8] ^= S[12];
			S[21] ^= S[10];
			S[22] ^= S[11];
			S[23] ^= S[12];
			smix( 6,  7,  8,  9);
			if (num -- <= 0) {
				rshift = 4;
				return;
			}
			w = (buf[off] << 24)
				| ((buf[off + 1] & 0xFF) << 16)
				| ((buf[off + 2] & 0xFF) << 8)
				| (buf[off + 3] & 0xFF);
			off += 4;
			/* ================ */
			S[16] ^= S[ 6];
			S[ 6] = w;
			S[14] ^= S[ 6];
			S[ 7] ^= S[ 0];
			S[ 3] ^= S[ 7];
			S[ 4] ^= S[ 8];
			S[ 5] ^= S[ 9];
			S[18] ^= S[ 7];
			S[19] ^= S[ 8];
			S[20] ^= S[ 9];
			smix( 3,  4,  5,  6);
			S[ 0] ^= S[ 4];
			S[ 1] ^= S[ 5];
			S[ 2] ^= S[ 6];
			S[15] ^= S[ 4];
			S[16] ^= S[ 5];
			S[17] ^= S[ 6];
			smix( 0,  1,  2,  3);
			if (num -- <= 0) {
				rshift = 0;
				return;
			}
			w = (buf[off] << 24)
				| ((buf[off + 1] & 0xFF) << 16)
				| ((buf[off + 2] & 0xFF) << 8)
				| (buf[off + 3] & 0xFF);
			off += 4;
		}
	}

	/** @see FugueCore */
	void processFinal(byte[] out)
	{
		int[] S = this.S;
		ror(6 * rshift, 30);
		for (int i = 0; i < 10; i ++) {
			ror(3, 30);
			cmix30();
			smix(0, 1, 2, 3);
		}
		for (int i = 0; i < 13; i ++) {
			S[ 4] ^= S[ 0];
			S[15] ^= S[ 0];
			ror(15, 30);
			smix(0, 1, 2, 3);
			S[ 4] ^= S[ 0];
			S[16] ^= S[ 0];
			ror(14, 30);
			smix(0, 1, 2, 3);
		}
		S[ 4] ^= S[ 0];
		S[15] ^= S[ 0];
		encodeBEInt(S[ 1], out,  0);
		encodeBEInt(S[ 2], out,  4);
		encodeBEInt(S[ 3], out,  8);
		encodeBEInt(S[ 4], out, 12);
		encodeBEInt(S[15], out, 16);
		encodeBEInt(S[16], out, 20);
		encodeBEInt(S[17], out, 24);
		if (out.length >= 32)
			encodeBEInt(S[18], out, 28);
	}
}
