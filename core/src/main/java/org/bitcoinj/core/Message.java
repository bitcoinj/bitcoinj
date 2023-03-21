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
import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;
import static org.bitcoinj.base.internal.Preconditions.checkState;

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

    protected MessageSerializer serializer;

    protected NetworkParameters params;

    protected Message() {
        serializer = DummySerializer.DEFAULT;
    }

    protected Message(NetworkParameters params) {
        this.params = params;
        this.serializer = params.getDefaultSerializer();
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

        parse();

        this.payload = null;
    }

    protected Message(NetworkParameters params, ByteBuffer payload) throws ProtocolException {
        this(params, payload, params.getDefaultSerializer());
    }

    // These methods handle the serialization/deserialization using the custom Bitcoin protocol.

    protected abstract void parse() throws ProtocolException;

    /**
     * <p>To be called before any change of internal values including any setters. This ensures any cached byte array is
     * removed.</p>
     * <p>Child messages of this object(e.g. Transactions belonging to a Block) will not have their internal byte caches
     * invalidated unless they are also modified internally.</p>
     */
    protected void unCache() {
    }

    /**
     * Overrides the message serializer.
     * @param serializer the new serializer
     */
    public void setSerializer(MessageSerializer serializer) {
        if (!this.serializer.equals(serializer)) {
            this.serializer = serializer;
            unCache();
        }
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

    protected long readUint32() throws ProtocolException {
        try {
            long u = ByteUtils.readUint32(payload);
            return u;
        } catch (BufferUnderflowException e) {
            throw new ProtocolException(e);
        }
    }

    protected long readInt64() throws ProtocolException {
        try {
            long u = ByteUtils.readInt64(payload);
            return u;
        } catch (BufferUnderflowException e) {
            throw new ProtocolException(e);
        }
    }

    protected BigInteger readUint64() throws ProtocolException {
        // Java does not have an unsigned 64 bit type. So scrape it off the wire then flip.
        return new BigInteger(ByteUtils.reverseBytes(readBytes(8)));
    }

    protected VarInt readVarInt() throws ProtocolException {
        try {
            return VarInt.read(payload);
        } catch (BufferUnderflowException e) {
            throw new ProtocolException(e);
        }
    }

    private void checkReadLength(int length) throws ProtocolException {
        if ((length > MAX_SIZE) || length > payload.remaining()) {
            throw new ProtocolException("Claimed value length too large: " + length);
        }
    }

    protected byte[] readBytes(int length) throws ProtocolException {
        checkReadLength(length);
        try {
            byte[] b = new byte[length];
            payload.get(b);
            return b;
        } catch (BufferUnderflowException e) {
            throw new ProtocolException(e);
        }
    }

    protected byte readByte() throws ProtocolException {
        checkReadLength(1);
        try {
            return payload.get();
        } catch (BufferUnderflowException e) {
            throw new ProtocolException(e);
        }
    }

    protected byte[] readByteArray() throws ProtocolException {
        final int length = readVarInt().intValue();
        return readBytes(length);
    }

    protected String readStr() throws ProtocolException {
        int length = readVarInt().intValue();
        return length == 0 ? "" : new String(readBytes(length), StandardCharsets.UTF_8); // optimization for empty strings
    }

    protected Sha256Hash readHash() throws ProtocolException {
        // We have to flip it around, as it's been read off the wire in little endian.
        // Not the most efficient way to do this but the clearest.
        return Sha256Hash.wrapReversed(readBytes(32));
    }

    protected void skipBytes(int numBytes) throws ProtocolException {
        checkArgument(numBytes >= 0);
        checkReadLength(numBytes);
        payload.position(payload.position() + numBytes);
    }

    /** Network parameters this message was created with. */
    public NetworkParameters getParams() {
        return params;
    }
}
