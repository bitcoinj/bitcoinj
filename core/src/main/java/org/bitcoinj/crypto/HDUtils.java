/*
 * Copyright 2013 Matija Mazi.
 * Copyright 2014 Giannis Dzegoutanis.
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

package org.bitcoinj.crypto;

import org.bitcoinj.core.ECKey;
import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import org.spongycastle.crypto.digests.SHA512Digest;
import org.spongycastle.crypto.macs.HMac;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nonnull;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Static utilities used in BIP 32 Hierarchical Deterministic Wallets (HDW).
 */
public final class HDUtils {
    private static final Joiner PATH_JOINER = Joiner.on("/");

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

    static byte[] toCompressed(byte[] uncompressedPoint) {
        return ECKey.CURVE.getCurve().decodePoint(uncompressedPoint).getEncoded(true);
    }

    static byte[] longTo4ByteArray(long n) {
        byte[] bytes = Arrays.copyOfRange(ByteBuffer.allocate(8).putLong(n).array(), 4, 8);
        assert bytes.length == 4 : bytes.length;
        return bytes;
    }

    /** Append a derivation level to an existing path */
    public static ImmutableList<ChildNumber> append(List<ChildNumber> path, ChildNumber childNumber) {
        return ImmutableList.<ChildNumber>builder().addAll(path).add(childNumber).build();
    }

    /** Concatenate two derivation paths */
    public static ImmutableList<ChildNumber> concat(List<ChildNumber> path, List<ChildNumber> path2) {
        return ImmutableList.<ChildNumber>builder().addAll(path).addAll(path2).build();
    }

    /** Convert to a string path, starting with "M/" */
    public static String formatPath(List<ChildNumber> path) {
        return PATH_JOINER.join(Iterables.concat(Collections.singleton("M"), path));
    }

    /**
     * The path is a human-friendly representation of the deterministic path. For example:
     *
     * "44H / 0H / 0H / 1 / 1"
     *
     * Where a letter "H" means hardened key. Spaces are ignored.
     */
    public static List<ChildNumber> parsePath(@Nonnull String path) {
        String[] parsedNodes = path.replace("M", "").split("/");
        List<ChildNumber> nodes = new ArrayList<>();

        for (String n : parsedNodes) {
            n = n.replaceAll(" ", "");
            if (n.length() == 0) continue;
            boolean isHard = n.endsWith("H");
            if (isHard) n = n.substring(0, n.length() - 1);
            int nodeNumber = Integer.parseInt(n);
            nodes.add(new ChildNumber(nodeNumber, isHard));
        }

        return nodes;
    }
}
