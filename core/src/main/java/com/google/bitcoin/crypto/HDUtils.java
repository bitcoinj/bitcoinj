/**
 * Copyright 2013 Matija Mazi.
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

package com.google.bitcoin.crypto;

import com.google.bitcoin.core.ECKey;
import com.google.common.collect.ImmutableList;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.math.ec.ECPoint;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Static utilities used in BIP 32 Hierarchical Deterministic Wallets (HDW).
 */
public final class HDUtils {

    private HDUtils() { }

    static HMac createHmacSha512Digest(byte[] key) {
        SHA512Digest digest = new SHA512Digest();
        HMac hMac = new HMac(digest);
        hMac.init(new KeyParameter(key));
        return hMac;
    }

    static byte[] hmacSha512(HMac hmacSha512, byte[] input) {
        hmacSha512.reset();
        hmacSha512.update(input, 0, input.length);
        byte[] out = new byte[64];
        hmacSha512.doFinal(out, 0);
        return out;
    }

    public static byte[] hmacSha512(byte[] key, byte[] data) {
        return hmacSha512(createHmacSha512Digest(key), data);
    }

    static ECPoint compressedCopy(ECPoint pubKPoint) {
        return ECKey.CURVE.getCurve().createPoint(pubKPoint.getX().toBigInteger(), pubKPoint.getY().toBigInteger(), true);
    }

    static ECPoint toUncompressed(ECPoint pubKPoint) {
        return ECKey.CURVE.getCurve().createPoint(pubKPoint.getX().toBigInteger(), pubKPoint.getY().toBigInteger(), false);
    }

    static byte[] toCompressed(byte[] uncompressedPoint) {
        return compressedCopy(ECKey.CURVE.getCurve().decodePoint(uncompressedPoint)).getEncoded();
    }

    static byte[] longTo4ByteArray(long n) {
        byte[] bytes = Arrays.copyOfRange(ByteBuffer.allocate(8).putLong(n).array(), 4, 8);
        assert bytes.length == 4 : bytes.length;
        return bytes;
    }

    static byte[] getBytes(ECPoint pubKPoint) {
        return compressedCopy(pubKPoint).getEncoded();
    }

    static ImmutableList<ChildNumber> append(ImmutableList<ChildNumber> path, ChildNumber childNumber) {
        return ImmutableList.<ChildNumber>builder().addAll(path).add(childNumber).build();
    }
}
