/*
 * Copyright 2011 Google Inc.
 * Copyright 2014 Andreas Schildbach
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Objects;

/**
 * <p>A Message is a data structure that can be serialized/deserialized using the Bitcoin serialization format.
 * Specific types of messages that are used both in the block chain, and on the wire, are derived from this
 * class.</p>
 * 
 * <p>Instances of this class are not safe for use by multiple threads.</p>
 */
public abstract class Message {
    private static final Logger log = LoggerFactory.getLogger(Message.class);

    public static final int MAX_SIZE = 0x02000000; // 32MB

    // The raw message payload bytes themselves.
    protected ByteBuffer payload;

    protected final MessageSerializer serializer;

    @Nullable
    protected final NetworkParameters params;

    protected Message() {
        this.params = null;
        this.serializer = DummySerializer.DEFAULT;
    }

    protected Message(NetworkParameters params) {
        this.params = params;
        this.serializer = params.getDefaultSerializer();
    }

    protected Message(MessageSerializer serializer) {
        this.params = null;
        this.serializer = serializer;
    }

    protected Message(NetworkParameters params, MessageSerializer serializer) {
        this.params = params;
        this.serializer = serializer;
    }

    /**
     * 
     * @param params NetworkParameters object.
     * @param payload Bitcoin protocol formatted byte array containing message content.
     * @param serializer the serializer to use for this message.
     * @throws ProtocolException
     */
    protected Message(NetworkParameters params, ByteBuffer payload, MessageSerializer serializer) throws ProtocolException {
        this.serializer = serializer;
        this.params = params;
        this.payload = payload;

        try {
            parse();
        } catch(BufferUnderflowException e) {
            throw new ProtocolException(e);
        }

        this.payload = null;
    }

    protected Message(ByteBuffer payload) throws ProtocolException {
        this(null, payload, DummySerializer.DEFAULT);
    }

    protected Message(ByteBuffer payload, MessageSerializer serializer) throws ProtocolException {
        this(null, payload, serializer);
    }

    protected Message(NetworkParameters params, ByteBuffer payload) throws ProtocolException {
        this(params, payload, params.getDefaultSerializer());
    }

    // These methods handle the serialization/deserialization using the custom Bitcoin protocol.

    protected abstract void parse() throws BufferUnderflowException, ProtocolException;

    /**
     * <p>To be called before any change of internal values including any setters. This ensures any cached byte array is
     * removed.</p>
     * <p>Child messages of this object(e.g. Transactions belonging to a Block) will not have their internal byte caches
     * invalidated unless they are also modified internally.</p>
     */
    protected void unCache() {
    }

    /**
     * <p>Serialize this message to a byte array that conforms to the bitcoin wire protocol.</p>
     *
     * @return a byte array
     */
    public final byte[] bitcoinSerialize() {
        // No cached array available so serialize parts by stream.
        ByteArrayOutputStream stream = new ByteArrayOutputStream(100); // initial size just a guess
        try {
            bitcoinSerializeToStream(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }
        return stream.toByteArray();
    }

    /** @deprecated use {@link #bitcoinSerialize()} */
    @Deprecated
    public byte[] unsafeBitcoinSerialize() {
        return bitcoinSerialize();
    }

    /**
     * Serializes this message to the provided stream. If you just want the raw bytes use bitcoinSerialize().
     */
    protected void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        log.error("Error: {} class has not implemented bitcoinSerializeToStream method.  Generating message with no payload", getClass());
    }

    /** @deprecated use {@link Transaction#getTxId()}, {@link Block#getHash()}, {@link FilteredBlock#getHash()} or {@link TransactionOutPoint#getHash()} */
    @Deprecated
    public Sha256Hash getHash() {
        throw new UnsupportedOperationException();
    }

    /**
     * Return the size of the serialized message. Note that if the message was deserialized from a payload, this
     * size can differ from the size of the original payload.
     * @return size of the serialized message in bytes
     */
    public int getMessageSize() {
        return bitcoinSerialize().length;
    }

    /** Network parameters this message was created with. */
    public NetworkParameters getParams() {
        return Objects.requireNonNull(params);
    }
}
