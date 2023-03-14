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

package org.bitcoinj.core;

import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.ByteUtils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

import static com.google.common.base.Preconditions.checkArgument;

public class Payload {
    public static Payload of(byte[] payload) {
        return new Payload(payload);
    }

    public static Payload ofHex(String hex) {
        return of(ByteUtils.parseHex(hex));
    }

    private final byte[] bytes;
    // The cursor keeps track of where we are in the byte array as we parse it.
    private int cursor;

    public Payload(byte[] bytes) {
        this.bytes = bytes;
        this.cursor = 0;
    }

    public byte[] bytes() {
        return bytes;
    }

    public int length() {
        return bytes.length;
    }

    public int cursor() {
        return cursor;
    }

    public void skip(int num) {
        checkArgument(num >= 0);
        cursor += num;
    }

    private void checkReadLength(int length) throws ProtocolException {
        if (length > Message.MAX_SIZE)
            throw new ProtocolException("claimed value length too large: " + length);
        if (cursor + length > bytes.length)
            throw new ProtocolException("claimed value length exceeds payload length: " + length);
    }

    public byte readByte() throws ProtocolException {
        checkReadLength(1);
        return bytes[cursor++];
    }

    public byte[] readBytes(int length) throws ProtocolException {
        checkReadLength(length);
        try {
            byte[] b = new byte[length];
            System.arraycopy(bytes, cursor, b, 0, length);
            cursor += length;
            return b;
        } catch (IndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    public byte[] readByteArray() throws ProtocolException {
        final int length = readVarInt().intValue();
        return readBytes(length);
    }

    public int readUint16BE() throws ProtocolException {
        try {
            int i = ByteUtils.readUint16BE(bytes, cursor);
            cursor += 2;
            return i;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    public long readUint32() throws ProtocolException {
        try {
            long u = ByteUtils.readUint32(bytes, cursor);
            cursor += 4;
            return u;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    public long readInt64() throws ProtocolException {
        try {
            long u = ByteUtils.readInt64(bytes, cursor);
            cursor += 8;
            return u;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    public BigInteger readUint64() throws ProtocolException {
        // Java does not have an unsigned 64 bit type. So scrape it off the wire then flip.
        return new BigInteger(ByteUtils.reverseBytes(readBytes(8)));
    }

    public VarInt readVarInt() throws ProtocolException {
        try {
            VarInt varint = new VarInt(bytes, cursor);
            cursor += varint.getOriginalSizeInBytes();
            return varint;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    public String readStr() throws ProtocolException {
        int length = readVarInt().intValue();
        return length == 0 ? "" : new String(readBytes(length), StandardCharsets.UTF_8); // optimization for empty strings
    }

    // TODO doesn't really belong here
    public Sha256Hash readHash() throws ProtocolException {
        // We have to flip it around, as it's been read off the wire in little endian.
        // Not the most efficient way to do this but the clearest.
        return Sha256Hash.wrapReversed(readBytes(32));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Payload other = (Payload) o;
        return Arrays.equals(this.bytes, other.bytes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(bytes);
    }

    @Override
    public String toString() {
        return ByteUtils.formatHex(bytes);
    }
}
