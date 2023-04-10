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

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.Buffers;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.Buffer;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.Random;
import java.util.stream.Stream;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;

@RunWith(JUnitParamsRunner.class)
public class BuffersTest {
    @Test
    @Parameters(method = "randomBytes")
    public void readAndWrite(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.allocate(VarInt.sizeOf(bytes.length) + bytes.length);
        Buffers.writeLengthPrefixedBytes(buf, bytes);
        assertFalse(buf.hasRemaining());
        ((Buffer) buf).rewind();
        byte[] copy = Buffers.readLengthPrefixedBytes(buf);
        assertFalse(buf.hasRemaining());
        assertArrayEquals(bytes, copy);
    }

    private Iterator<byte[]> randomBytes() {
        Random random = new Random();
        return Stream.generate(() -> {
            int length = random.nextInt(10);
            byte[] bytes = new byte[length];
            random.nextBytes(bytes);
            return bytes;
        }).limit(10).iterator();
    }

    // If readStr() is vulnerable this causes OutOfMemory
    @Test(expected = BufferUnderflowException.class)
    public void readStrOfExtremeLength() {
        VarInt length = VarInt.of(Integer.MAX_VALUE);
        ByteBuffer payload = ByteBuffer.wrap(length.serialize());
        Buffers.readLengthPrefixedString(payload);
    }

    // If readBytes() is vulnerable this causes OutOfMemory
    @Test(expected = BufferUnderflowException.class)
    public void readByteArrayOfExtremeLength() {
        VarInt length = VarInt.of(Integer.MAX_VALUE);
        ByteBuffer payload = ByteBuffer.wrap(length.serialize());
        Buffers.readLengthPrefixedBytes(payload);
    }
}
