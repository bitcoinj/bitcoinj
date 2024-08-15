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

package org.bitcoinj.core.internal;

import com.google.common.io.BaseEncoding;
import org.bouncycastle.jcajce.provider.digest.SHA3;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;

/**
 * Utilities for encoding and decoding Onion addresses.
 */
public class TorUtils {

    private static final BaseEncoding BASE32 = BaseEncoding.base32().omitPadding().lowerCase();

    /**
     * Encode an Onion URL from a Tor V2 address.
     * <p>
     * See <a href="https://github.com/torproject/torspec/blob/main/address-spec.txt">address-spec.txt</a>
     *
     * @param onionAddrBytes Tor V2 address to encode
     * @return encoded Onion URL
     */
    public static String encodeOnionUrlV2(byte[] onionAddrBytes) {
        checkArgument(onionAddrBytes.length == 10);
        return BASE32.encode(onionAddrBytes) + ".onion";
    }

    /**
     * Encode an Onion URL from a Tor V3 address (pubkey).
     * <p>
     * See <a href="https://github.com/torproject/torspec/blob/main/address-spec.txt">address-spec.txt</a>
     *
     * @param onionAddrBytes Tor V3 address to encode
     * @return encoded Onion URL
     */
    public static String encodeOnionUrlV3(byte[] onionAddrBytes) {
        checkArgument(onionAddrBytes.length == 32);
        byte torVersion = 0x03;
        byte[] onionAddress = new byte[35];
        System.arraycopy(onionAddrBytes, 0, onionAddress, 0, 32);
        System.arraycopy(onionChecksum(onionAddrBytes, torVersion), 0, onionAddress, 32, 2);
        onionAddress[34] = torVersion;
        return BASE32.encode(onionAddress) + ".onion";
    }

    /**
     * Decode an Onion URL into a Tor V2 or V3 address.
     * <p>
     * See <a href="https://github.com/torproject/torspec/blob/main/address-spec.txt">address-spec.txt</a>
     *
     * @param onionUrl Onion URL to decode
     * @return decoded Tor address
     */
    public static byte[] decodeOnionUrl(String onionUrl) {
        if (!onionUrl.toLowerCase(Locale.ROOT).endsWith(".onion"))
            throw new IllegalArgumentException("not an onion URL: " + onionUrl);
        byte[] onionAddress = BASE32.decode(onionUrl.substring(0, onionUrl.length() - 6));
        if (onionAddress.length == 10) {
            // TORv2
            return onionAddress;
        } else if (onionAddress.length == 32 + 2 + 1) {
            // TORv3
            byte[] pubkey = Arrays.copyOfRange(onionAddress, 0, 32);
            byte[] checksum = Arrays.copyOfRange(onionAddress, 32, 34);
            byte torVersion = onionAddress[34];
            if (torVersion != 0x03)
                throw new IllegalArgumentException("unknown version: " + onionUrl);
            if (!Arrays.equals(checksum, onionChecksum(pubkey, torVersion)))
                throw new IllegalArgumentException("bad checksum: " + onionUrl);
            return pubkey;
        } else {
            throw new IllegalArgumentException("unrecognizable length: " + onionUrl);
        }
    }

    /**
     * Calculate Onion Checksum
     */
    private static byte[] onionChecksum(byte[] pubkey, byte version) {
        if (pubkey.length != 32)
            throw new IllegalArgumentException();
        SHA3.Digest256 digest256 = new SHA3.Digest256();
        digest256.update(".onion checksum".getBytes(StandardCharsets.US_ASCII));
        digest256.update(pubkey);
        digest256.update(version);
        return Arrays.copyOf(digest256.digest(), 2);
    }
}
