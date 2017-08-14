/*
 * Copyright (c) 2012 Cole Barnes [cryptofreek{at}gmail{dot}com]
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 */

package org.bitcoincashj.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * <p>This is a clean-room implementation of PBKDF2 using RFC 2898 as a reference.</p>
 *
 * <p>RFC 2898: http://tools.ietf.org/html/rfc2898#section-5.2</p>
 *
 * <p>This code passes all RFC 6070 test vectors: http://tools.ietf.org/html/rfc6070</p>
 *
 * <p>http://cryptofreek.org/2012/11/29/pbkdf2-pure-java-implementation/<br>
 * Modified to use SHA-512 - Ken Sedgwick ken@bonsai.com</p>
 */
public class PBKDF2SHA512 {
    public static byte[] derive(String P, String S, int c, int dkLen) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            int hLen = 20;

            if (dkLen > ((Math.pow(2, 32)) - 1) * hLen) {
                throw new IllegalArgumentException("derived key too long");
            } else {
                int l = (int) Math.ceil((double) dkLen / (double) hLen);
                // int r = dkLen - (l-1)*hLen;

                for (int i = 1; i <= l; i++) {
                    byte[] T = F(P, S, c, i);
                    baos.write(T);
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        byte[] baDerived = new byte[dkLen];
        System.arraycopy(baos.toByteArray(), 0, baDerived, 0, baDerived.length);

        return baDerived;
    }

    private static byte[] F(String P, String S, int c, int i) throws Exception {
        byte[] U_LAST = null;
        byte[] U_XOR = null;

        SecretKeySpec key = new SecretKeySpec(P.getBytes("UTF-8"), "HmacSHA512");
        Mac mac = Mac.getInstance(key.getAlgorithm());
        mac.init(key);

        for (int j = 0; j < c; j++) {
            if (j == 0) {
                byte[] baS = S.getBytes("UTF-8");
                byte[] baI = INT(i);
                byte[] baU = new byte[baS.length + baI.length];

                System.arraycopy(baS, 0, baU, 0, baS.length);
                System.arraycopy(baI, 0, baU, baS.length, baI.length);

                U_XOR = mac.doFinal(baU);
                U_LAST = U_XOR;
                mac.reset();
            } else {
                byte[] baU = mac.doFinal(U_LAST);
                mac.reset();

                for (int k = 0; k < U_XOR.length; k++) {
                    U_XOR[k] = (byte) (U_XOR[k] ^ baU[k]);
                }

                U_LAST = baU;
            }
        }

        return U_XOR;
    }

    private static byte[] INT(int i) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.order(ByteOrder.BIG_ENDIAN);
        bb.putInt(i);

        return bb.array();
    }
}
