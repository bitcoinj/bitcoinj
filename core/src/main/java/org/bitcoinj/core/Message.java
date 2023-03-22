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
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

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

    public static final int UNKNOWN_LENGTH = Integer.MIN_VALUE;

    // The offset is how many bytes into the provided byte array this message payload starts at.
    protected int offset;
    // The cursor keeps track of where we are in the byte array as we parse it.
    // Note that it's relative to the start of the array NOT the start of the message payload.
    protected int cursor;

    protected int length = UNKNOWN_LENGTH;

    // The raw message payload bytes themselves.
    protected byte[] payload;

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
        // unwrap ByteBuffer into individual fields
        this.length = payload.remaining();
        this.payload = new byte[this.length];
        payload.get(this.payload);
        this.cursor = this.offset = 0;

        parse();

        checkState(this.length != UNKNOWN_LENGTH || this instanceof UnknownMessage, () ->
                "length field has not been set in constructor for " + getClass().getSimpleName() + " after parse");

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

    protected void adjustLength(int newArraySize, int adjustment) {
        if (length == UNKNOWN_LENGTH)
            return;
        // Our own length is now unknown if we have an unknown length adjustment.
        if (adjustment == UNKNOWN_LENGTH) {
            length = UNKNOWN_LENGTH;
            return;
        }
        length += adjustment;
        // Check if we will need more bytes to encode the length prefix.
        if (newArraySize == 1)
            length++;  // The assumption here is we never call adjustLength with the same arraySize as before.
        else if (newArraySize != 0)
            length += VarInt.sizeOf(newArraySize) - VarInt.sizeOf(newArraySize - 1);
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
     * Returns a copy of the array returned by {@link Message#unsafeBitcoinSerialize()}, which is safe to mutate.
     * If you need extra performance and can guarantee you won't write to the array, you can use the unsafe version.
     *
     * @return a freshly allocated serialized byte array
     */
    public byte[] bitcoinSerialize() {
        byte[] bytes = unsafeBitcoinSerialize();
        byte[] copy = new byte[bytes.length];
        System.arraycopy(bytes, 0, copy, 0, bytes.length);
        return copy;
    }

    /**
     * <p>Serialize this message to a byte array that conforms to the bitcoin wire protocol.</p>
     *
     * <p>This method may return the original byte array used to construct this message if the
     * following conditions are met:</p>
     *
     * <ol>
     * <li>1) The message was parsed from a byte array with parseRetain = true</li>
     * <li>2) The message has not been modified</li>
     * <li>3) The array had an offset of 0 and no surplus bytes</li>
     * </ol>
     *
     * <p>If condition 3 is not met then an copy of the relevant portion of the array will be returned.
     * Otherwise a full serialize will occur. For this reason you should only use this API if you can guarantee you
     * will treat the resulting array as read only.</p>
     *
     * @return a byte array owned by this object, do NOT mutate it.
     */
    public byte[] unsafeBitcoinSerialize() {
        // No cached array available so serialize parts by stream.
        ByteArrayOutputStream stream = new ByteArrayOutputStream(length < 32 ? 32 : length + 32);
        try {
            bitcoinSerializeToStream(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }

        // Record length. If this Message wasn't parsed from a byte stream it won't have length field
        // set (except for static length message types).  Setting it makes future streaming more efficient
        // because we can preallocate the ByteArrayOutputStream buffer and avoid resizing.
        byte[] buf = stream.toByteArray();
        length = buf.length;
        return buf;
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
     * This returns a correct value by parsing the message.
     */
    public final int getMessageSize() {
        checkState(length != UNKNOWN_LENGTH, () ->
                "length field has not been set in " + getClass().getSimpleName());
        return length;
    }

    protected long readUint32() throws ProtocolException {
        try {
            long u = ByteUtils.readUint32(payload, cursor);
            cursor += 4;
            return u;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected long readInt64() throws ProtocolException {
        try {
            long u = ByteUtils.readInt64(payload, cursor);
            cursor += 8;
            return u;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected BigInteger readUint64() throws ProtocolException {
        // Java does not have an unsigned 64 bit type. So scrape it off the wire then flip.
        return new BigInteger(ByteUtils.reverseBytes(readBytes(8)));
    }

    protected VarInt readVarInt() throws ProtocolException {
        try {
            VarInt varint = VarInt.ofBytes(payload, cursor);
            cursor += varint.getOriginalSizeInBytes();
            return varint;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    private void checkReadLength(int length) throws ProtocolException {
        if ((length > MAX_SIZE) || (cursor + length > payload.length)) {
            throw new ProtocolException("Claimed value length too large: " + length);
        }
    }

    protected byte[] readBytes(int length) throws ProtocolException {
        checkReadLength(length);
        try {
            byte[] b = new byte[length];
            System.arraycopy(payload, cursor, b, 0, length);
            cursor += length;
            return b;
        } catch (IndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    protected byte readByte() throws ProtocolException {
        checkReadLength(1);
        return payload[cursor++];
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

    /** Network parameters this message was created with. */
    public NetworkParameters getParams() {
        return params;
    }
}
