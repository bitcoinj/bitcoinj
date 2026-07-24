/*
 * Copyright by the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.base;

/**
 * MurmurHash3 (x86_32) utility.
 */
public class MurmurHash3 {
    private MurmurHash3() {
    }

    /**
     * Applies the MurmurHash3 (x86_32) algorithm to the given data.
     * See this <a href="https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp">C++ code for the original.</a>
     */
    public static int murmurHash3(byte[] data, long nTweak, int hashNum, byte[] object) {
        int h1 = (int)(hashNum * 0xFBA4C795L + nTweak);
        final int c1 = 0xcc9e2d51;
        final int c2 = 0x1b873593;

        int numBlocks = (object.length / 4) * 4;
        // body
        for (int i = 0; i < numBlocks; i += 4) {
            int k1 = (object[i] & 0xFF)
                    | ((object[i + 1] & 0xFF) << 8)
                    | ((object[i + 2] & 0xFF) << 16)
                    | ((object[i + 3] & 0xFF) << 24);

            k1 *= c1;
            k1 = rotateLeft32(k1, 15);
            k1 *= c2;

            h1 ^= k1;
            h1 = rotateLeft32(h1, 13);
            h1 = h1 * 5 + 0xe6546b64;
        }

        int k1 = 0;
        switch (object.length & 3) {
            case 3:
                k1 ^= (object[numBlocks + 2] & 0xff) << 16;
                // Fall through.
            case 2:
                k1 ^= (object[numBlocks + 1] & 0xff) << 8;
                // Fall through.
            case 1:
                k1 ^= (object[numBlocks] & 0xff);
                k1 *= c1; k1 = rotateLeft32(k1, 15); k1 *= c2; h1 ^= k1;
                // Fall through.
            default:
                // Do nothing.
                break;
        }

        // finalization
        h1 ^= object.length;
        h1 ^= h1 >>> 16;
        h1 *= 0x85ebca6b;
        h1 ^= h1 >>> 13;
        h1 *= 0xc2b2ae35;
        h1 ^= h1 >>> 16;

        return (int)((h1&0xFFFFFFFFL) % (data.length * 8));
    }

    private static int rotateLeft32(int x, int r) {
        return (x << r) | (x >>> (32 - r));
    }
}
