/**
 * Copyright 2011 Google Inc.
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

package com.google.bitcoin.core;

import java.util.Arrays;

import static com.google.common.base.Preconditions.checkArgument;

/**
 * <p>In Bitcoin the following format is often used to represent some type of key:</p>
 * <p/>
 * <pre>[one version byte] [data bytes] [4 checksum bytes]</pre>
 * <p/>
 * <p>and the result is then Base58 encoded. This format is used for addresses, and private keys exported using the
 * dumpprivkey command.</p>
 */
public class VersionedChecksummedBytes {
    protected int version;
    protected byte[] bytes;

    protected VersionedChecksummedBytes(String encoded) throws AddressFormatException {
        byte[] tmp = Base58.decodeChecked(encoded);
        version = tmp[0] & 0xFF;
        bytes = new byte[tmp.length - 1];
        System.arraycopy(tmp, 1, bytes, 0, tmp.length - 1);
    }

    protected VersionedChecksummedBytes(int version, byte[] bytes) {
        checkArgument(version < 256 && version >= 0);
        this.version = version;
        this.bytes = bytes;
    }

    @Override
    public String toString() {
        // A stringified buffer is:
        //   1 byte version + data bytes + 4 bytes check code (a truncated hash)
        byte[] addressBytes = new byte[1 + bytes.length + 4];
        addressBytes[0] = (byte) version;
        System.arraycopy(bytes, 0, addressBytes, 1, bytes.length);
        byte[] check = Utils.doubleDigest(addressBytes, 0, bytes.length + 1);
        System.arraycopy(check, 0, addressBytes, bytes.length + 1, 4);
        return Base58.encode(addressBytes);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof VersionedChecksummedBytes)) return false;
        VersionedChecksummedBytes vcb = (VersionedChecksummedBytes) o;
        return Arrays.equals(vcb.bytes, bytes);
    }

    /**
     * Returns the "version" or "header" byte: the first byte of the data. This is used to disambiguate what the
     * contents apply to, for example, which network the key or address is valid on.
     *
     * @return A positive number between 0 and 255.
     */
    public int getVersion() {
        return version;
    }
}
