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
package org.bitcoinj.core;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * Generic interface for classes which serialize/deserialize messages. Implementing
 * classes should be immutable.
 */
public interface MessageSerializer {

    /**
     * Reads a message from the given ByteBuffer and returns it.
     */
    Message deserialize(ByteBuffer in) throws ProtocolException, IOException, UnsupportedOperationException;

    /**
     * Deserializes only the header in case packet meta data is needed before decoding
     * the payload. This method assumes you have already called seekPastMagicBytes()
     */
    BitcoinSerializer.BitcoinPacketHeader deserializeHeader(ByteBuffer in) throws ProtocolException, IOException, UnsupportedOperationException;

    /**
     * Deserialize payload only.  You must provide a header, typically obtained by calling
     * {@link BitcoinSerializer#deserializeHeader}.
     */
    Message deserializePayload(BitcoinSerializer.BitcoinPacketHeader header, ByteBuffer in) throws ProtocolException, BufferUnderflowException, UnsupportedOperationException;

    /**
     * Whether the serializer will produce lazy parse mode Messages
     */
    boolean isParseLazyMode();

    /**
     * Whether the serializer will produce cached mode Messages
     */
    boolean isParseRetainMode();

    /**
     * Make an address message from the payload. Extension point for alternative
     * serialization format support.
     */
    AddressMessage makeAddressMessage(byte[] payloadBytes, int length) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make an alert message from the payload. Extension point for alternative
     * serialization format support.
     */
    Message makeAlertMessage(byte[] payloadBytes) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make a block from the payload. Extension point for alternative
     * serialization format support.
     */
    Block makeBlock(byte[] payloadBytes) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make a block from the payload. Extension point for alternative
     * serialization format support.
     */
    Block makeBlock(byte[] payloadBytes, int length) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make an filter message from the payload. Extension point for alternative
     * serialization format support.
     */
    Message makeBloomFilter(byte[] payloadBytes) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make a filtered block from the payload. Extension point for alternative
     * serialization format support.
     */
    FilteredBlock makeFilteredBlock(byte[] payloadBytes) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make an inventory message from the payload. Extension point for alternative
     * serialization format support.
     */
    InventoryMessage makeInventoryMessage(byte[] payloadBytes, int length) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make a transaction from the payload. Extension point for alternative
     * serialization format support.
     * 
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support deserialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support deserializing transactions.
     */
    Transaction makeTransaction(byte[] payloadBytes, int offset, int length, byte[] hash) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make a transaction from the payload. Extension point for alternative
     * serialization format support.
     * 
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support deserialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support deserializing transactions.
     */
    Transaction makeTransaction(byte[] payloadBytes) throws ProtocolException, UnsupportedOperationException;

    /**
     * Make a transaction from the payload. Extension point for alternative
     * serialization format support.
     * 
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support deserialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support deserializing transactions.
     */
    Transaction makeTransaction(byte[] payloadBytes, int offset) throws ProtocolException, UnsupportedOperationException;

    void seekPastMagicBytes(ByteBuffer in) throws BufferUnderflowException;

    /**
     * Writes message to to the output stream.
     * 
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support serialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support serializing the given message.
     */
    void serialize(String name, byte[] message, OutputStream out) throws IOException, UnsupportedOperationException;

    /**
     * Writes message to to the output stream.
     * 
     * @throws UnsupportedOperationException if this serializer/deserializer
     * does not support serialization. This can occur either because it's a dummy
     * serializer (i.e. for messages with no network parameters), or because
     * it does not support serializing the given message.
     */
    void serialize(Message message, OutputStream out) throws IOException, UnsupportedOperationException;
    
}
