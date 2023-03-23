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

package org.bitcoinj.base.internal;

import org.bitcoinj.base.VarInt;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.bitcoinj.base.internal.Preconditions.check;
import static org.bitcoinj.base.internal.Preconditions.checkArgument;
import static org.bitcoinj.base.internal.Preconditions.checkState;

public class Buffers {
    /**
     * Read given number of bytes from the buffer.
     *
     * @param buf    buffer to read from
     * @param length number of bytes to read
     * @return bytes read
     * @throws BufferUnderflowException if the read value extends beyond the remaining bytes of the buffer
     */
    public static byte[] readBytes(ByteBuffer buf, int length) throws BufferUnderflowException {
        // defensive check against cheap memory exhaustion attack
        check(length <= buf.remaining(), BufferUnderflowException::new);
        byte[] b = new byte[length];
        buf.get(b);
        return b;
    }

    /**
     * First read a {@link VarInt} to determine the number of bytes to read. Then read that number of bytes from the
     * buffer. This construct is frequently used by the Bitcoin protocol.
     *
     * @param buf buffer to read from
     * @return read bytes
     * @throws BufferUnderflowException if the read value extends beyond the remaining bytes of the buffer
     */
    public static byte[] readByteArray(ByteBuffer buf) throws BufferUnderflowException {
        int length = VarInt.read(buf).intValue();
        return readBytes(buf, length);
    }

    /**
     * First read a {@link VarInt} to determine the number of bytes to read. Then read that number of bytes from the
     * buffer and interpret it as an UTF-8 encoded string. This construct is frequently used by the Bitcoin protocol.
     *
     * @param buf buffer to read from
     * @return read string
     * @throws BufferUnderflowException if the read value extends beyond the remaining bytes of the buffer
     */
    public static String readString(ByteBuffer buf) throws BufferUnderflowException {
        return new String(readByteArray(buf), StandardCharsets.UTF_8);
    }

    /**
     * Advance buffer position by a given number of bytes.
     *
     * @param buf      buffer to skip bytes on
     * @param numBytes number of bytes to skip
     * @return the buffer
     * @throws BufferUnderflowException if the read value extends beyond the remaining bytes of the buffer
     */
    public static ByteBuffer skipBytes(ByteBuffer buf, int numBytes) throws BufferUnderflowException {
        checkArgument(numBytes >= 0);
        check(numBytes <= buf.remaining(), BufferUnderflowException::new);
        buf.position(buf.position() + numBytes);
        return buf;
    }
}
