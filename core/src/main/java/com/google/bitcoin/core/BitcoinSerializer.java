/**
 * Copyright 2011 Google Inc.
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

package com.google.bitcoin.core;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
import java.util.Map;

import static com.google.bitcoin.core.Utils.*;

/**
 * <p>Methods to serialize and de-serialize messages to the Bitcoin network format as defined in
 * <a href="https://en.bitcoin.it/wiki/Protocol_specification">the protocol specification</a>.</p>
 *
 * <p>To be able to serialize and deserialize new Message subclasses the following criteria needs to be met.</p>
 *
 * <ul>
 * <li>The proper Class instance needs to be mapped to it's message name in the names variable below</li>
 * <li>There needs to be a constructor matching: NetworkParameters params, byte[] payload</li>
 * <li>Message.bitcoinSerializeToStream() needs to be properly subclassed</li>
 * </ul>
 */
public class BitcoinSerializer {
    private static final Logger log = LoggerFactory.getLogger(BitcoinSerializer.class);
    private static final int COMMAND_LEN = 12;

    private NetworkParameters params;
    private boolean parseLazy = false;
    private boolean parseRetain = false;

    private static Map<Class<? extends Message>, String> names = new HashMap<Class<? extends Message>, String>();

    static {
        names.put(VersionMessage.class, "version");
        names.put(InventoryMessage.class, "inv");
        names.put(Block.class, "block");
        names.put(GetDataMessage.class, "getdata");
        names.put(Transaction.class, "tx");
        names.put(AddressMessage.class, "addr");
        names.put(Ping.class, "ping");
        names.put(Pong.class, "pong");
        names.put(VersionAck.class, "verack");
        names.put(GetBlocksMessage.class, "getblocks");
        names.put(GetHeadersMessage.class, "getheaders");
        names.put(GetAddrMessage.class, "getaddr");
        names.put(HeadersMessage.class, "headers");
        names.put(BloomFilter.class, "filterload");
        names.put(FilteredBlock.class, "merkleblock");
        names.put(NotFoundMessage.class, "notfound");
        names.put(MemoryPoolMessage.class, "mempool");
    }

    /**
     * Constructs a BitcoinSerializer with the given behavior.
     *
     * @param params           networkParams used to create Messages instances and termining packetMagic
     */
    public BitcoinSerializer(NetworkParameters params) {
        this(params, false, false);
    }

    /**
     * Constructs a BitcoinSerializer with the given behavior.
     *
     * @param params           networkParams used to create Messages instances and termining packetMagic
     * @param parseLazy        deserialize messages in lazy mode.
     * @param parseRetain      retain the backing byte array of a message for fast reserialization.
     */
    public BitcoinSerializer(NetworkParameters params, boolean parseLazy, boolean parseRetain) {
        this.params = params;
        this.parseLazy = parseLazy;
        this.parseRetain = parseRetain;
    }

    /**
     * Writes message to to the output stream.
     */
    public void serialize(Message message, OutputStream out) throws IOException {
        String name = names.get(message.getClass());
        if (name == null) {
            throw new Error("BitcoinSerializer doesn't currently know how to serialize " + message.getClass());
        }

        byte[] header = new byte[4 + COMMAND_LEN + 4 + 4 /* checksum */];
        uint32ToByteArrayBE(params.packetMagic, header, 0);

        // The header array is initialized to zero by Java so we don't have to worry about
        // NULL terminating the string here.
        for (int i = 0; i < name.length() && i < COMMAND_LEN; i++) {
            header[4 + i] = (byte) (name.codePointAt(i) & 0xFF);
        }

        byte[] payload = message.bitcoinSerialize();

        Utils.uint32ToByteArrayLE(payload.length, header, 4 + COMMAND_LEN);

        byte[] checksum = message.getChecksum();
        if (checksum == null) {
            Sha256Hash msgHash = message.getHash();
            if (msgHash != null && message instanceof Transaction) {
                // if the message happens to have a precalculated hash use
                // it.
                // reverse copying 4 bytes is about 1600 times faster than
                // calculating a new hash
                // this is only possible for transactions as block hashes
                // are hashes of the header only
                byte[] hash = msgHash.getBytes();
                int start = 4 + COMMAND_LEN + 4;
                for (int i = start; i < start + 4; i++)
                    header[i] = hash[31 - i + start];

            } else {
                byte[] hash = doubleDigest(payload);
                System.arraycopy(hash, 0, header, 4 + COMMAND_LEN + 4, 4);
            }
        } else {
            System.arraycopy(checksum, 0, header, 4 + COMMAND_LEN + 4, 4);
        }

        out.write(header);
        out.write(payload);

        if (log.isDebugEnabled())
            log.debug("Sending {} message: {}", name, bytesToHexString(header) + bytesToHexString(payload));
    }

    /**
     * Reads a message from the given InputStream and returns it.
     */
    public Message deserialize(InputStream in) throws ProtocolException, IOException {
        // A Bitcoin protocol message has the following format.
        //
        //   - 4 byte magic number: 0xfabfb5da for the testnet or
        //                          0xf9beb4d9 for production
        //   - 12 byte command in ASCII
        //   - 4 byte payload size
        //   - 4 byte checksum
        //   - Payload data
        //
        // The checksum is the first 4 bytes of a SHA256 hash of the message payload. It isn't
        // present for all messages, notably, the first one on a connection.
        //
        // Satoshi's implementation ignores garbage before the magic header bytes. We have to do the same because
        // sometimes it sends us stuff that isn't part of any message.
        seekPastMagicBytes(in);
        BitcoinPacketHeader header = new BitcoinPacketHeader(in);
        // Now try to read the whole message.
        return deserializePayload(header, in);
    }

    /**
     * Deserializes only the header in case packet meta data is needed before decoding
     * the payload. This method assumes you have already called seekPastMagicBytes()
     */
    public BitcoinPacketHeader deserializeHeader(InputStream in) throws ProtocolException, IOException {
        return new BitcoinPacketHeader(in);
    }

    /**
     * Deserialize payload only.  You must provide a header, typically obtained by calling
     * {@link BitcoinSerializer#deserializeHeader}.
     */
    public Message deserializePayload(BitcoinPacketHeader header, InputStream in) throws ProtocolException, IOException {
        int readCursor = 0;
        byte[] payloadBytes = new byte[header.size];
        while (readCursor < payloadBytes.length - 1) {
            int bytesRead = in.read(payloadBytes, readCursor, header.size - readCursor);
            if (bytesRead == -1) {
                throw new IOException("Socket is disconnected");
            }
            readCursor += bytesRead;
        }

        // Verify the checksum.
        byte[] hash;
        hash = doubleDigest(payloadBytes);
        if (header.checksum[0] != hash[0] || header.checksum[1] != hash[1] ||
                header.checksum[2] != hash[2] || header.checksum[3] != hash[3]) {
            throw new ProtocolException("Checksum failed to verify, actual " +
                    bytesToHexString(hash) +
                    " vs " + bytesToHexString(header.checksum));
        }

        if (log.isDebugEnabled()) {
            log.debug("Received {} byte '{}' message: {}", new Object[]{
                    header.size,
                    header.command,
                    Utils.bytesToHexString(payloadBytes)
            });
        }

        try {
            return makeMessage(header.command, header.size, payloadBytes, hash, header.checksum);
        } catch (Exception e) {
            throw new ProtocolException("Error deserializing message " + Utils.bytesToHexString(payloadBytes) + "\n", e);
        }
    }

    private Message makeMessage(String command, int length, byte[] payloadBytes, byte[] hash, byte[] checksum) throws ProtocolException {
        // We use an if ladder rather than reflection because reflection is very slow on Android.
        Message message;
        if (command.equals("version")) {
            return new VersionMessage(params, payloadBytes);
        } else if (command.equals("inv")) {
            message = new InventoryMessage(params, payloadBytes, parseLazy, parseRetain, length);
        } else if (command.equals("block")) {
            message = new Block(params, payloadBytes, parseLazy, parseRetain, length);
        } else if (command.equals("merkleblock")) {
            message = new FilteredBlock(params, payloadBytes);
        } else if (command.equals("getdata")) {
            message = new GetDataMessage(params, payloadBytes, parseLazy, parseRetain, length);
        } else if (command.equals("tx")) {
            Transaction tx = new Transaction(params, payloadBytes, null, parseLazy, parseRetain, length);
            if (hash != null)
                tx.setHash(new Sha256Hash(Utils.reverseBytes(hash)));
            message = tx;
        } else if (command.equals("addr")) {
            message = new AddressMessage(params, payloadBytes, parseLazy, parseRetain, length);
        } else if (command.equals("ping")) {
            message = new Ping(params, payloadBytes);
        } else if (command.equals("pong")) {
            message = new Pong(params, payloadBytes);
        } else if (command.equals("verack")) {
            return new VersionAck(params, payloadBytes);
        } else if (command.equals("headers")) {
            return new HeadersMessage(params, payloadBytes);
        } else if (command.equals("alert")) {
            return new AlertMessage(params, payloadBytes);
        } else if (command.equals("filterload")) {
            return new BloomFilter(params, payloadBytes);
        } else if (command.equals("notfound")) {
            return new NotFoundMessage(params, payloadBytes);
        } else if (command.equals("mempool")) {
            return new MemoryPoolMessage();
        } else {
            log.warn("No support for deserializing message with name {}", command);
            return new UnknownMessage(params, command, payloadBytes);
        }
        if (checksum != null)
            message.setChecksum(checksum);
        return message;
    }

    public void seekPastMagicBytes(InputStream in) throws IOException {
        int magicCursor = 3;  // Which byte of the magic we're looking for currently.
        while (true) {
            int b = in.read();  // Read a byte.
            if (b == -1) {
                // There's no more data to read.
                throw new IOException("Socket is disconnected");
            }
            // We're looking for a run of bytes that is the same as the packet magic but we want to ignore partial
            // magics that aren't complete. So we keep track of where we're up to with magicCursor.
            int expectedByte = 0xFF & (int) (params.packetMagic >>> (magicCursor * 8));
            if (b == expectedByte) {
                magicCursor--;
                if (magicCursor < 0) {
                    // We found the magic sequence.
                    return;
                } else {
                    // We still have further to go to find the next message.
                }
            } else {
                magicCursor = 3;
            }
        }
    }

    /**
     * Whether the serializer will produce lazy parse mode Messages
     */
    public boolean isParseLazyMode() {
        return parseLazy;
    }

    /**
     * Whether the serializer will produce cached mode Messages
     */
    public boolean isParseRetainMode() {
        return parseRetain;
    }


    public static class BitcoinPacketHeader {
        public final byte[] header;
        public final String command;
        public final int size;
        public final byte[] checksum;

        public BitcoinPacketHeader(InputStream in) throws ProtocolException, IOException {
            header = new byte[COMMAND_LEN + 4 + 4];
            int readCursor = 0;
            while (readCursor < header.length) {
                int bytesRead = in.read(header, readCursor, header.length - readCursor);
                if (bytesRead == -1) {
                    // There's no more data to read.
                    throw new IOException("Incomplete packet in underlying stream");
                }
                readCursor += bytesRead;
            }

            int cursor = 0;

            // The command is a NULL terminated string, unless the command fills all twelve bytes
            // in which case the termination is implicit.
            int mark = cursor;
            for (; header[cursor] != 0 && cursor - mark < COMMAND_LEN; cursor++) ;
            byte[] commandBytes = new byte[cursor - mark];
            System.arraycopy(header, mark, commandBytes, 0, cursor - mark);
            try {
                command = new String(commandBytes, "US-ASCII");
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);  // Cannot happen.
            }
            cursor = mark + COMMAND_LEN;

            size = (int) readUint32(header, cursor);
            cursor += 4;

            if (size > Message.MAX_SIZE)
                throw new ProtocolException("Message size too large: " + size);

            // Old clients don't send the checksum.
            checksum = new byte[4];
            // Note that the size read above includes the checksum bytes.
            System.arraycopy(header, cursor, checksum, 0, 4);
            cursor += 4;
        }
    }
}
