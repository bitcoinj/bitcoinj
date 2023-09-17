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

package org.bitcoinj.crypto;

import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.base.internal.Preconditions;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * This is a clean-room implementation of PBKDF2 using RFC 2898 as a reference.
 * Modified to use SHA-512 by Ken Sedgwick (ken@bonsai.com)
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2898#section-5.2">RFC 2898 (Section 5.2)</a>
 * @see <a href="https://cryptofreek.org/2012/11/29/pbkdf2-pure-java-implementation/">PBKDF2 – Pure Java Implementation by Cryptofreek</a>
 */
public class PBKDF2SHA512 {
    // Length of HMAC result
    private static final int H_LEN = 64;

    /**
     * Derive a key using PBKDF2-SHA512
     * @param P password
     * @param S salt
     * @param c iteration count, a positive integer
     * @param dkLen intended length in octets of the derived key, a positive integer
     * @return derived key
     */
    public static byte[] derive(String P, String S, int c, int dkLen) {
        Preconditions.checkArgument(c > 0, () -> "count must be greater than zero");
        Preconditions.checkArgument(dkLen > 0, () -> "derived key length must be greater than zero");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // The algorithm in RFC 2898 section 5.2, says to check `dkLen` is not greater than (2^32 - 1) * `H_LEN`
        // But that is not possible given `dkLen` is an `int` argument, so we omit the check.
        try {
            int l = (dkLen + H_LEN - 1) / H_LEN;    // Divide by H_LEN with rounding up
            // int r = dkLen - (l-1)*hLen;

            for (int i = 1; i <= l; i++) {
                byte[] T = F(P, S, c, i);
                baos.write(T);
            }
        } catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        byte[] baDerived = new byte[dkLen];
        System.arraycopy(baos.toByteArray(), 0, baDerived, 0, baDerived.length);

        return baDerived;
    }

    private static byte[] F(String P, String S, int c, int i) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] U_LAST = null;
        byte[] U_XOR = null;

        SecretKeySpec key = new SecretKeySpec(P.getBytes(StandardCharsets.UTF_8), "HmacSHA512");
        Mac mac = Mac.getInstance(key.getAlgorithm());
        mac.init(key);

        for (int j = 0; j < c; j++) {
            if (j == 0) {
                byte[] baU = ByteUtils.concat(S.getBytes(StandardCharsets.UTF_8), INT(i));

                U_XOR = mac.doFinal(baU);
                U_LAST = U_XOR;
            } else {
                byte[] baU = mac.doFinal(U_LAST);

                for (int k = 0; k < U_XOR.length; k++) {
                    U_XOR[k] = (byte) (U_XOR[k] ^ baU[k]);
                }

                U_LAST = baU;
            }
        }

        return U_XOR;
    }

    private static byte[] INT(int i) {
        return ByteBuffer.allocate(4)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(i)
                .array();
    }
}
