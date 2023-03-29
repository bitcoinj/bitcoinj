/*
 * Copyright 2014 Piotr Włodarek
 * Copyright 2015 Andreas Schildbach
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

import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.Buffers;
import org.bitcoinj.params.TestNet3Params;
import org.junit.Test;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

public class MessageTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();

    // If readStr() is vulnerable this causes OutOfMemory
    @Test(expected = ProtocolException.class)
    public void readStrOfExtremeLength() {
        VarInt length = VarInt.of(Integer.MAX_VALUE);
        ByteBuffer payload = ByteBuffer.wrap(length.encode());
        new VarStrMessage(TESTNET, payload);
    }

    static class VarStrMessage extends Message {
        public VarStrMessage(NetworkParameters params, ByteBuffer payload) {
            super(params, payload);
        }

        @Override
        protected void parse() throws BufferUnderflowException, ProtocolException {
            Buffers.readLengthPrefixedString(payload);
        }
    }

    // If readBytes() is vulnerable this causes OutOfMemory
    @Test(expected = ProtocolException.class)
    public void readByteArrayOfExtremeLength() {
        VarInt length = VarInt.of(Integer.MAX_VALUE);
        ByteBuffer payload = ByteBuffer.wrap(length.encode());
        new VarBytesMessage(payload);
    }

    static class VarBytesMessage extends Message {
        public VarBytesMessage(ByteBuffer payload) {
            super(payload);
        }

        @Override
        protected void parse() throws BufferUnderflowException, ProtocolException {
            Buffers.readLengthPrefixedBytes(payload);
        }
    }
}
