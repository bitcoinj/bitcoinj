/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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

package org.bitcoincashj.core;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * Generic interface for classes which serialize/deserialize messages. Implementing
 * classes should be immutable.
 */
public abstract class MessageSerializer {

    /**
     * Reads a message from the given ByteBuffer and returns it.
     */
    public abstract Message deserialize(ByteBuffer in) throws ProtocolException, IOException, UnsupportedOperationException;

    /**
     * Deserializes only the header in case packet meta data is needed before decoding
     * the payload. This method assumes you have already called seekPastMagicBytes()
     */
    public abstract BitcoinSerializer.BitcoinPacketHeader deserializeHeader(ByteBuffer in) throws ProtocolException, IOException, UnsupportedOperationException;

    /**
     * Deserialize payload only.  You must provide a header, typically obtained by calling
     * {@link BitcoinSerializer#deserializeHeader}.
     */
    public abstract Message deserializePayload(BitcoinSerializer.BitcoinPacketHeader header, ByteBuffer in) throws ProtocolException, BufferUnderflowException, UnsupportedOperationException;

    /**
     * Whether the serializer will produce cached mode Messages
     */
    public abstract boolean isParseRetainMode();

    /**
     * Make an address message from the payload. Extension point for alternative
     * serialization format support.
     */
    public abstract AddressMessage makeAddressMessage(byte[] payloadBytes, int length) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make an alert message from the payload. Extension point for alternative
     * serialization format support.
     */
    public abstract Message makeAlertMessage(byte[] payloadBytes) throws ProtocolException, UnsupportedOperationException;


    /**
     * Make a block from the payload, using an offset of zero and the payload
     * length as block length.
     */
    public final Block makeBlock(byte[] payloadBytes) throws ProtocolException {
        return makeBlock(payloadBytes, 0, payloadBytes.length);
    }

    /**
     * Make a block from the payload, using an offset of zero and the provided
     * length as block length.
     */
    public final Block makeBlock(byte[] payloadBytes, int length) throws ProtocolException {
        return makeBlock(payloadBytes, 0, length);
    }

    /**
     * Make a block from the payload, using an offset of zero and the provided
     * length as block length. Extension point for alternative
     * serialization format support.
     */
    public abstract Block makeBlock(final byte[] payloadBytes, final int offset, final int length) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make an filter message from the payload. Extension point for alternative
     * serialization format support.
     */
    public abstract Message makeBloomFilter(byte[] payloadBytes) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make a filtered block from the payload. Extension point for alternative
     * serialization format support.
     */
    public abstract FilteredBlock makeFilteredBlock(byte[] payloadBytes) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make an inventory message from the payload. Extension point for alternative
     * serialization format support.
     */
    public abstract InventoryMessage makeInventoryMessage(byte[] payloadBytes, int length) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make a transaction from the payload. Extension point for alternative
     * serialization format support.
     * 
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support deserialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support deserializing transactions.
     */
    public abstract Transaction makeTransaction(byte[] payloadBytes, int offset, int length, byte[] hash) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make a transaction from the payload. Extension point for alternative
     * serialization format support.
     * 
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support deserialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support deserializing transactions.
     */
    public final Transaction makeTransaction(byte[] payloadBytes) throws ProtocolException, UnsupportedOperationException {
        return makeTransaction(payloadBytes, 0);
    }

    /**
     * Make a transaction from the payload. Extension point for alternative
     * serialization format support.
     * 
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support deserialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support deserializing transactions.
     */
    public final Transaction makeTransaction(byte[] payloadBytes, int offset) throws ProtocolException {
        return makeTransaction(payloadBytes, offset, payloadBytes.length, null);
    }

    public abstract void seekPastMagicBytes(ByteBuffer in) throws BufferUnderflowException;

    /**
     * Writes message to to the output stream.
     * 
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support serialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support serializing the given message.
     */
    public abstract void serialize(String name, byte[] message, OutputStream out) throws IOException, UnsupportedOperationException;

    /**
     * Writes message to to the output stream.
     * 
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support serialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support serializing the given message.
     */
    public abstract void serialize(Message message, OutputStream out) throws IOException, UnsupportedOperationException;
    
}
