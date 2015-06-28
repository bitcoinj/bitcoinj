/**
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.math.BigInteger;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkState;

/**
 * <p>A Message is a data structure that can be serialized/deserialized using both the Bitcoin proprietary serialization
 * format and built-in Java object serialization. Specific types of messages that are used both in the block chain,
 * and on the wire, are derived from this class.</p>
 */
public abstract class Message implements Serializable {
    private static final Logger log = LoggerFactory.getLogger(Message.class);
    private static final long serialVersionUID = -3561053461717079135L;

    public static final int MAX_SIZE = 0x02000000; // 32MB

    public static final int UNKNOWN_LENGTH = Integer.MIN_VALUE;

    // Useful to ensure serialize/deserialize are consistent with each other.
    private static final boolean SELF_CHECK = false;

    // The offset is how many bytes into the provided byte array this message payload starts at.
    protected transient int offset;
    // The cursor keeps track of where we are in the byte array as we parse it.
    // Note that it's relative to the start of the array NOT the start of the message payload.
    protected transient int cursor;

    protected transient int length = UNKNOWN_LENGTH;

    // The raw message payload bytes themselves.
    protected transient byte[] payload;

    protected transient boolean parsed = false;
    protected transient boolean recached = false;
    protected final transient boolean parseLazy;
    protected final transient boolean parseRetain;

    protected transient int protocolVersion;

    protected transient byte[] checksum;

    // This will be saved by subclasses that implement Serializable.
    protected NetworkParameters params;

    /**
     * This exists for the Java serialization framework to use only.
     */
    protected Message() {
        parsed = true;
        parseLazy = false;
        parseRetain = false;
    }

    Message(NetworkParameters params) {
        this.params = params;
        parsed = true;
        parseLazy = false;
        parseRetain = false;
    }

    Message(NetworkParameters params, byte[] payload, int offset, int protocolVersion) throws ProtocolException {
        this(params, payload, offset, protocolVersion, false, false, UNKNOWN_LENGTH);
    }

    /**
     * 
     * @param params NetworkParameters object.
     * @param payload Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first payload byte within the array.
     * @param protocolVersion Bitcoin protocol version.
     * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
     * If true and the backing byte array is invalidated due to modification of a field then 
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @param length The length of message payload if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    Message(NetworkParameters params, byte[] payload, int offset, int protocolVersion, boolean parseLazy, boolean parseRetain, int length) throws ProtocolException {
        this.parseLazy = parseLazy;
        this.parseRetain = parseRetain;
        this.protocolVersion = protocolVersion;
        this.params = params;
        this.payload = payload;
        this.cursor = this.offset = offset;
        this.length = length;
        if (parseLazy) {
            parseLite();
        } else {
            parseLite();
            parse();
            parsed = true;
        }

        if (this.length == UNKNOWN_LENGTH)
            checkState(false, "Length field has not been set in constructor for %s after %s parse. " +
                              "Refer to Message.parseLite() for detail of required Length field contract.",
                       getClass().getSimpleName(), parseLazy ? "lite" : "full");
        
        if (SELF_CHECK) {
            selfCheck(payload, offset);
        }
        
        if (parseRetain || !parsed)
            return;
        this.payload = null;
    }

    private void selfCheck(byte[] payload, int offset) {
        if (!(this instanceof VersionMessage)) {
            maybeParse();
            byte[] payloadBytes = new byte[cursor - offset];
            System.arraycopy(payload, offset, payloadBytes, 0, cursor - offset);
            byte[] reserialized = bitcoinSerialize();
            if (!Arrays.equals(reserialized, payloadBytes))
                throw new RuntimeException("Serialization is wrong: \n" +
                        Utils.HEX.encode(reserialized) + " vs \n" +
                        Utils.HEX.encode(payloadBytes));
        }
    }

    Message(NetworkParameters params, byte[] payload, int offset) throws ProtocolException {
        this(params, payload, offset, NetworkParameters.PROTOCOL_VERSION, false, false, UNKNOWN_LENGTH);
    }

    Message(NetworkParameters params, byte[] payload, int offset, boolean parseLazy, boolean parseRetain, int length) throws ProtocolException {
        this(params, payload, offset, NetworkParameters.PROTOCOL_VERSION, parseLazy, parseRetain, length);
    }

    // These methods handle the serialization/deserialization using the custom Bitcoin protocol.
    // It's somewhat painful to work with in Java, so some of these objects support a second
    // serialization mechanism - the standard Java serialization system. This is used when things
    // are serialized to the wallet.
    abstract void parse() throws ProtocolException;

    /**
     * Perform the most minimal parse possible to calculate the length of the message payload.
     * This is only required for subclasses of ChildMessage as root level messages will have their length passed
     * into the constructor.
     * <p/>
     * Implementations should adhere to the following contract:  If parseLazy = true the 'length'
     * field must be set before returning.  If parseLazy = false the length field must be set either
     * within the parseLite() method OR the parse() method.  The overriding requirement is that length
     * must be set to non UNKNOWN_MESSAGE value by the time the constructor exits.
     *
     * @return
     * @throws ProtocolException
     */
    protected abstract void parseLite() throws ProtocolException;

    /**
     * Ensure the object is parsed if needed.  This should be called in every getter before returning a value.
     * If the lazy parse flag is not set this is a method returns immediately.
     */
    protected synchronized void maybeParse() {
        if (parsed || payload == null)
            return;
        try {
            parse();
            parsed = true;
            if (!parseRetain)
                payload = null;
        } catch (ProtocolException e) {
            throw new LazyParseException("ProtocolException caught during lazy parse.  For safe access to fields call ensureParsed before attempting read or write access", e);
        }
    }

    /**
     * In lazy parsing mode access to getters and setters may throw an unchecked LazyParseException.  If guaranteed safe access is required
     * this method will force parsing to occur immediately thus ensuring LazyParseExeption will never be thrown from this Message.
     * If the Message contains child messages (e.g. a Block containing Transaction messages) this will not force child messages to parse.
     * <p/>
     * This could be overidden for Transaction and it's child classes to ensure the entire tree of Message objects is parsed.
     *
     * @throws ProtocolException
     */
    public void ensureParsed() throws ProtocolException {
        try {
            maybeParse();
        } catch (LazyParseException e) {
            if (e.getCause() instanceof ProtocolException)
                throw (ProtocolException) e.getCause();
            throw new ProtocolException(e);
        }
    }

    /**
     * To be called before any change of internal values including any setters.  This ensures any cached byte array is
     * removed after performing a lazy parse if necessary to ensure the object is fully populated.
     * <p/>
     * Child messages of this object(e.g. Transactions belonging to a Block) will not have their internal byte caches
     * invalidated unless they are also modified internally.
     */
    protected void unCache() {
        maybeParse();
        checksum = null;
        payload = null;
        recached = false;
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
     * used for unit testing
     */
    public boolean isParsed() {
        return parsed;
    }

    /**
     * used for unit testing
     */
    public boolean isCached() {
        return payload != null;
    }

    public boolean isRecached() {
        return recached;
    }

    /**
     * Should only used by BitcoinSerializer for cached checksum
     *
     * @return the checksum
     */
    byte[] getChecksum() {
        return checksum;
    }

    /**
     * Should only used by BitcoinSerializer for caching checksum
     *
     * @param checksum the checksum to set
     */
    void setChecksum(byte[] checksum) {
        if (checksum.length != 4)
            throw new IllegalArgumentException("Checksum length must be 4 bytes, actual length: " + checksum.length);
        this.checksum = checksum;
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
     * Serialize this message to a byte array that conforms to the bitcoin wire protocol.
     * <br/>
     * This method may return the original byte array used to construct this message if the
     * following conditions are met:
     * <ol>
     * <li>1) The message was parsed from a byte array with parseRetain = true</li>
     * <li>2) The message has not been modified</li>
     * <li>3) The array had an offset of 0 and no surplus bytes</li>
     * </ol>
     *
     * If condition 3 is not met then an copy of the relevant portion of the array will be returned.
     * Otherwise a full serialize will occur. For this reason you should only use this API if you can guarantee you
     * will treat the resulting array as read only.
     *
     * @return a byte array owned by this object, do NOT mutate it.
     */
    public byte[] unsafeBitcoinSerialize() {
        // 1st attempt to use a cached array.
        if (payload != null) {
            if (offset == 0 && length == payload.length) {
                // Cached byte array is the entire message with no extras so we can return as is and avoid an array
                // copy.
                return payload;
            }

            byte[] buf = new byte[length];
            System.arraycopy(payload, offset, buf, 0, length);
            return buf;
        }

        // No cached array available so serialize parts by stream.
        ByteArrayOutputStream stream = new UnsafeByteArrayOutputStream(length < 32 ? 32 : length + 32);
        try {
            bitcoinSerializeToStream(stream);
        } catch (IOException e) {
            // Cannot happen, we are serializing to a memory stream.
        }

        if (parseRetain) {
            // A free set of steak knives!
            // If there happens to be a call to this method we gain an opportunity to recache
            // the byte array and in this case it contains no bytes from parent messages.
            // This give a dual benefit.  Releasing references to the larger byte array so that it
            // it is more likely to be GC'd.  And preventing double serializations.  E.g. calculating
            // merkle root calls this method.  It is will frequently happen prior to serializing the block
            // which means another call to bitcoinSerialize is coming.  If we didn't recache then internal
            // serialization would occur a 2nd time and every subsequent time the message is serialized.
            payload = stream.toByteArray();
            cursor = cursor - offset;
            offset = 0;
            recached = true;
            length = payload.length;
            return payload;
        }
        // Record length. If this Message wasn't parsed from a byte stream it won't have length field
        // set (except for static length message types).  Setting it makes future streaming more efficient
        // because we can preallocate the ByteArrayOutputStream buffer and avoid resizing.
        byte[] buf = stream.toByteArray();
        length = buf.length;
        return buf;
    }

    /**
     * Serialize this message to the provided OutputStream using the bitcoin wire format.
     *
     * @param stream
     * @throws IOException
     */
    public final void bitcoinSerialize(OutputStream stream) throws IOException {
        // 1st check for cached bytes.
        if (payload != null && length != UNKNOWN_LENGTH) {
            stream.write(payload, offset, length);
            return;
        }

        bitcoinSerializeToStream(stream);
    }

    /**
     * Serializes this message to the provided stream. If you just want the raw bytes use bitcoinSerialize().
     */
    void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        log.error("Error: {} class has not implemented bitcoinSerializeToStream method.  Generating message with no payload", getClass());
    }

    /**
     * This method is a NOP for all classes except Block and Transaction.  It is only declared in Message
     * so BitcoinSerializer can avoid 2 instanceof checks + a casting.
     */
    public Sha256Hash getHash() {
        throw new UnsupportedOperationException();
    }

    /**
     * This should be overridden to extract correct message size in the case of lazy parsing.  Until this method is
     * implemented in a subclass of ChildMessage lazy parsing may have no effect.
     *
     * This default implementation is a safe fall back that will ensure it returns a correct value by parsing the message.
     */
    public int getMessageSize() {
        if (length != UNKNOWN_LENGTH)
            return length;
        maybeParse();
        if (length == UNKNOWN_LENGTH)
            checkState(false, "Length field has not been set in %s after full parse.", getClass().getSimpleName());
        return length;
    }

    long readUint32() throws ProtocolException {
        try {
            long u = Utils.readUint32(payload, cursor);
            cursor += 4;
            return u;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    long readInt64() throws ProtocolException {
        try {
            long u = Utils.readInt64(payload, cursor);
            cursor += 8;
            return u;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    BigInteger readUint64() throws ProtocolException {
        // Java does not have an unsigned 64 bit type. So scrape it off the wire then flip.
        return new BigInteger(Utils.reverseBytes(readBytes(8)));
    }

    long readVarInt() throws ProtocolException {
        return readVarInt(0);
    }

    long readVarInt(int offset) throws ProtocolException {
        try {
            VarInt varint = new VarInt(payload, cursor + offset);
            cursor += offset + varint.getOriginalSizeInBytes();
            return varint.value;
        } catch (ArrayIndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }

    byte[] readBytes(int length) throws ProtocolException {
        if (length > MAX_SIZE) {
            throw new ProtocolException("Claimed value length too large: " + length);
        }
        try {
            byte[] b = new byte[length];
            System.arraycopy(payload, cursor, b, 0, length);
            cursor += length;
            return b;
        } catch (IndexOutOfBoundsException e) {
            throw new ProtocolException(e);
        }
    }
    
    byte[] readByteArray() throws ProtocolException {
        long len = readVarInt();
        return readBytes((int)len);
    }

    String readStr() throws ProtocolException {
        long length = readVarInt();
        return length == 0 ? "" : Utils.toString(readBytes((int) length), "UTF-8"); // optimization for empty strings
    }

    Sha256Hash readHash() throws ProtocolException {
        // We have to flip it around, as it's been read off the wire in little endian.
        // Not the most efficient way to do this but the clearest.
        return Sha256Hash.wrapReversed(readBytes(32));
    }

    boolean hasMoreBytes() {
        return cursor < payload.length;
    }

    /** Network parameters this message was created with. */
    public NetworkParameters getParams() {
        return params;
    }

    public static class LazyParseException extends RuntimeException {
        private static final long serialVersionUID = 6971943053112975594L;

        public LazyParseException(String message, Throwable cause) {
            super(message, cause);
        }

        public LazyParseException(String message) {
            super(message);
        }

    }
}
