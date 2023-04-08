/*
 * Copyright 2015 Ross Nicoll
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.core;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * Dummy serializer used ONLY for objects which do not have network parameters
 * set.
 */
class DummySerializer extends MessageSerializer {
    public static final DummySerializer DEFAULT = new DummySerializer();

    private static final String DEFAULT_EXCEPTION_MESSAGE = "Dummy serializer cannot serialize/deserialize objects as it does not know which network they belong to.";

    private final int protocolVersion;

    public DummySerializer() {
        this.protocolVersion = 0;
    }

    public DummySerializer(int protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    @Override
    public DummySerializer withProtocolVersion(int protocolVersion) {
        return new DummySerializer(protocolVersion);
    }

    @Override
    public int getProtocolVersion() {
        return protocolVersion;
    }

    @Override
    public Message deserialize(ByteBuffer in) throws UnsupportedOperationException {
        throw new UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE);
    }

    @Override
    public BitcoinSerializer.BitcoinPacketHeader deserializeHeader(ByteBuffer in) throws UnsupportedOperationException {
        throw new UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE);
    }

    @Override
    public Message deserializePayload(BitcoinSerializer.BitcoinPacketHeader header, ByteBuffer in) throws UnsupportedOperationException {
        throw new UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE);
    }

    @Override
    public AddressV1Message makeAddressV1Message(ByteBuffer payload) throws UnsupportedOperationException {
        throw new UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE);
    }

    @Override
    public AddressV2Message makeAddressV2Message(ByteBuffer payload) throws UnsupportedOperationException {
        throw new UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE);
    }

    @Override
    public Block makeBlock(ByteBuffer payload) throws UnsupportedOperationException {
        throw new UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE);
    }

    @Override
    public Message makeBloomFilter(ByteBuffer payload) throws UnsupportedOperationException {
        throw new UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE);
    }

    @Override
    public FilteredBlock makeFilteredBlock(ByteBuffer payload) throws UnsupportedOperationException {
        throw new UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE);
    }

    @Override
    public InventoryMessage makeInventoryMessage(ByteBuffer payload) throws UnsupportedOperationException {
        throw new UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE);
    }

    @Override
    public Transaction makeTransaction(ByteBuffer payload) throws UnsupportedOperationException {
        throw new UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE);
    }

    @Override
    public void seekPastMagicBytes(ByteBuffer in) throws BufferUnderflowException {
        throw new UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE);
    }

    @Override
    public void serialize(String name, byte[] message, OutputStream out) throws IOException {
        throw new UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE);
    }

    @Override
    public void serialize(Message message, OutputStream out) throws IOException {
        throw new UnsupportedOperationException(DEFAULT_EXCEPTION_MESSAGE);
    }
    
}
