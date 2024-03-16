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

import org.bitcoinj.base.Network;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.internal.ByteUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.bitcoinj.base.internal.ByteUtils.readUint32;
import static org.bitcoinj.base.internal.Preconditions.check;

/**
 * <p>Methods to serialize and de-serialize messages to the Bitcoin network format as defined in
 * <a href="https://en.bitcoin.it/wiki/Protocol_specification">the protocol specification</a>.</p>
 *
 * <p>To be able to serialize and deserialize new Message subclasses the following criteria needs to be met.</p>
 *
 * <ul>
 * <li>The proper Class instance needs to be mapped to its message name in the names variable below</li>
 * <li>There needs to be a constructor matching: NetworkParameters params, byte[] payload</li>
 * <li>Message.bitcoinSerializeToStream() needs to be properly subclassed</li>
 * </ul>
 */
public class BitcoinSerializer extends MessageSerializer {
    private static final Logger log = LoggerFactory.getLogger(BitcoinSerializer.class);
    private static final int COMMAND_LEN = 12;

    private final Network network;
    private final int packetMagic;
    private final int protocolVersion;

    private static final Map<Class<? extends Message>, String> names = new HashMap<>();

    static {
        names.put(VersionMessage.class, "version");
        names.put(InventoryMessage.class, "inv");
        names.put(Block.class, "block");
        names.put(GetDataMessage.class, "getdata");
        names.put(Transaction.class, "tx");
        names.put(AddressV1Message.class, "addr");
        names.put(AddressV2Message.class, "addrv2");
        names.put(Ping.class, "ping");
        names.put(Pong.class, "pong");
        names.put(VersionAck.class, "verack");
        names.put(GetBlocksMessage.class, "getblocks");
        names.put(GetHeadersMessage.class, "getheaders");
        names.put(GetAddrMessage.class, "getaddr");
        names.put(SendAddrV2Message.class, "sendaddrv2");
        names.put(HeadersMessage.class, "headers");
        names.put(BloomFilter.class, "filterload");
        names.put(FilteredBlock.class, "merkleblock");
        names.put(NotFoundMessage.class, "notfound");
        names.put(MemoryPoolMessage.class, "mempool");
        names.put(RejectMessage.class, "reject");
        names.put(SendHeadersMessage.class, "sendheaders");
        names.put(FeeFilterMessage.class, "feefilter");
    }

    /**
     * Constructs a BitcoinSerializer with the given behavior.
     *
     * @param params networkParams used to determine packetMagic
     */
    @Deprecated
    public BitcoinSerializer(NetworkParameters params) {
        this(params.network());
    }

    /**
     * Constructs a BitcoinSerializer with the given behavior.
     *
     * @param network used to determine packetMagic
     */
    public BitcoinSerializer(Network network) {
        this(network, ProtocolVersion.CURRENT.intValue());
    }

    /**
     * Constructs a BitcoinSerializer with the given behavior.
     *
     * @param params networkParams used to determine packetMagic
     * @param protocolVersion the protocol version to use
     */
    @Deprecated
    public BitcoinSerializer(NetworkParameters params, int protocolVersion) {
        this(params.network, protocolVersion);
    }

    /**
     * Constructs a BitcoinSerializer with the given behavior.
     *
     * @param network used to determine packetMagic
     * @param protocolVersion the protocol version to use
     */
    public BitcoinSerializer(Network network, int protocolVersion) {
        this.network = network;
        this.packetMagic = NetworkParameters.of(network).getPacketMagic();
        this.protocolVersion = protocolVersion;
    }

    @Override
    public BitcoinSerializer withProtocolVersion(int protocolVersion) {
        return protocolVersion == this.protocolVersion ?
                this : new BitcoinSerializer(network, protocolVersion);
    }

    @Override
    public int getProtocolVersion() {
        return protocolVersion;
    }

    /**
     * Writes message to the output stream.
     */
    @Override
    public void serialize(String name, byte[] message, OutputStream out) throws IOException {
        byte[] header = new byte[4 + COMMAND_LEN + 4 + 4 /* checksum */];
        ByteUtils.writeInt32BE(packetMagic, header, 0);

        // The header array is initialized to zero by Java so we don't have to worry about
        // NULL terminating the string here.
        for (int i = 0; i < name.length() && i < COMMAND_LEN; i++) {
            header[4 + i] = (byte) (name.codePointAt(i) & 0xFF);
        }

        ByteUtils.writeInt32LE(message.length, header, 4 + COMMAND_LEN);

        byte[] hash = Sha256Hash.hashTwice(message);
        System.arraycopy(hash, 0, header, 4 + COMMAND_LEN + 4, 4);
        out.write(header);
        out.write(message);

        if (log.isDebugEnabled())
            log.debug("Sending {} message: {}", name, ByteUtils.formatHex(header) + ByteUtils.formatHex(message));
    }

    /**
     * Writes message to the output stream.
     */
    @Override
    public void serialize(Message message, OutputStream out) throws IOException {
        String name = names.get(message.getClass());
        if (name == null) {
            throw new Error("BitcoinSerializer doesn't currently know how to serialize " + message.getClass());
        }
        serialize(name, message.serialize(), out);
    }

    /**
     * Reads a message from the given ByteBuffer and returns it.
     */
    @Override
    public Message deserialize(ByteBuffer in) throws ProtocolException, IOException {
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
        // Bitcoin Core ignores garbage before the magic header bytes. We have to do the same because
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
    @Override
    public BitcoinPacketHeader deserializeHeader(ByteBuffer in) throws ProtocolException, IOException {
        return new BitcoinPacketHeader(in);
    }

    /**
     * Deserialize payload only.  You must provide a header, typically obtained by calling
     * {@link BitcoinSerializer#deserializeHeader}.
     */
    @Override
    public Message deserializePayload(BitcoinPacketHeader header, ByteBuffer in) throws ProtocolException, BufferUnderflowException {
        byte[] payloadBytes = new byte[header.size];
        in.get(payloadBytes, 0, header.size);

        // Verify the checksum.
        byte[] hash;
        hash = Sha256Hash.hashTwice(payloadBytes);
        if (header.checksum[0] != hash[0] || header.checksum[1] != hash[1] ||
                header.checksum[2] != hash[2] || header.checksum[3] != hash[3]) {
            throw new ProtocolException("Checksum failed to verify, actual " +
                    ByteUtils.formatHex(hash) +
                    " vs " + ByteUtils.formatHex(header.checksum));
        }

        if (log.isDebugEnabled()) {
            log.debug("Received {} byte '{}' message: {}", header.size, header.command,
                    ByteUtils.formatHex(payloadBytes));
        }

        try {
            return makeMessage(header.command, payloadBytes, hash);
        } catch (Exception e) {
            throw new ProtocolException("Error deserializing message " + ByteUtils.formatHex(payloadBytes) + "\n", e);
        }
    }

    private Message makeMessage(String command, byte[] payloadBytes, byte[] hash) throws ProtocolException {
        ByteBuffer payload = ByteBuffer.wrap(payloadBytes);
        // We use an if ladder rather than reflection because reflection is very slow on Android.
        if (command.equals("version")) {
            return VersionMessage.read(payload);
        } else if (command.equals("inv")) {
            return makeInventoryMessage(payload);
        } else if (command.equals("block")) {
            return makeBlock(payload);
        } else if (command.equals("merkleblock")) {
            return makeFilteredBlock(payload);
        } else if (command.equals("getdata")) {
            return GetDataMessage.read(payload);
        } else if (command.equals("getblocks")) {
            return GetBlocksMessage.read(payload);
        } else if (command.equals("getheaders")) {
            return GetHeadersMessage.read(payload);
        } else if (command.equals("tx")) {
            return makeTransaction(payload);
        } else if (command.equals("sendaddrv2")) {
            check(!payload.hasRemaining(), ProtocolException::new);
            return new SendAddrV2Message();
        } else if (command.equals("addr")) {
            return makeAddressV1Message(payload);
        } else if (command.equals("addrv2")) {
            return makeAddressV2Message(payload);
        } else if (command.equals("ping")) {
            return Ping.read(payload);
        } else if (command.equals("pong")) {
            return Pong.read(payload);
        } else if (command.equals("verack")) {
            check(!payload.hasRemaining(), ProtocolException::new);
            return new VersionAck();
        } else if (command.equals("headers")) {
            return HeadersMessage.read(payload);
        } else if (command.equals("filterload")) {
            return makeBloomFilter(payload);
        } else if (command.equals("notfound")) {
            return NotFoundMessage.read(payload);
        } else if (command.equals("mempool")) {
            return new MemoryPoolMessage();
        } else if (command.equals("reject")) {
            return RejectMessage.read(payload);
        } else if (command.equals("sendheaders")) {
            check(!payload.hasRemaining(), ProtocolException::new);
            return new SendHeadersMessage();
        } else if (command.equals("feefilter")) {
            return FeeFilterMessage.read(payload);
        } else {
            check(!payload.hasRemaining(), ProtocolException::new);
            return new UnknownMessage(command);
        }
    }

    /**
     * Get the network parameters for this serializer.
     */
    @Deprecated
    public NetworkParameters getParameters() {
        return NetworkParameters.of(network);
    }

    /**
     * Make an address message from the payload. Extension point for alternative
     * serialization format support.
     */
    @Override
    public AddressV1Message makeAddressV1Message(ByteBuffer payload) throws ProtocolException {
        return AddressV1Message.read(payload);
    }

    /**
     * Make an address message from the payload. Extension point for alternative
     * serialization format support.
     */
    @Override
    public AddressV2Message makeAddressV2Message(ByteBuffer payload) throws ProtocolException {
        return AddressV2Message.read(payload);
    }

    /**
     * Make a block from the payload. Extension point for alternative
     * serialization format support.
     */
    @Override
    public Block makeBlock(ByteBuffer payload) throws ProtocolException {
        return Block.read(payload);
    }

    /**
     * Make an filter message from the payload. Extension point for alternative
     * serialization format support.
     */
    @Override
    public Message makeBloomFilter(ByteBuffer payload) throws ProtocolException {
        return BloomFilter.read(payload);
    }

    /**
     * Make a filtered block from the payload. Extension point for alternative
     * serialization format support.
     */
    @Override
    public FilteredBlock makeFilteredBlock(ByteBuffer payload) throws ProtocolException {
        return FilteredBlock.read(payload);
    }

    /**
     * Make an inventory message from the payload. Extension point for alternative
     * serialization format support.
     */
    @Override
    public InventoryMessage makeInventoryMessage(ByteBuffer payload) throws ProtocolException {
        return InventoryMessage.read(payload);
    }

    /**
     * Make a transaction from the payload. Extension point for alternative
     * serialization format support.
     */
    @Override
    public Transaction makeTransaction(ByteBuffer payload)
            throws ProtocolException {
        return Transaction.read(payload, protocolVersion);
    }

    @Override
    public void seekPastMagicBytes(ByteBuffer in) throws BufferUnderflowException {
        int magicCursor = 3;  // Which byte of the magic we're looking for currently.
        while (true) {
            byte b = in.get();
            // We're looking for a run of bytes that is the same as the packet magic but we want to ignore partial
            // magics that aren't complete. So we keep track of where we're up to with magicCursor.
            byte expectedByte = (byte)(0xFF & packetMagic >>> (magicCursor * 8));
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

    public static class BitcoinPacketHeader {
        /** The largest number of bytes that a header can represent */
        public static final int HEADER_LENGTH = COMMAND_LEN + 4 + 4;

        public final byte[] header;
        public final String command;
        public final int size;
        public final byte[] checksum;

        public BitcoinPacketHeader(ByteBuffer in) throws ProtocolException, BufferUnderflowException {
            header = new byte[HEADER_LENGTH];
            in.get(header, 0, header.length);

            int cursor = 0;

            // The command is a NULL terminated string, unless the command fills all twelve bytes
            // in which case the termination is implicit.
            for (; header[cursor] != 0 && cursor < COMMAND_LEN; cursor++) ;
            byte[] commandBytes = new byte[cursor];
            System.arraycopy(header, 0, commandBytes, 0, cursor);
            command = new String(commandBytes, StandardCharsets.US_ASCII);
            cursor = COMMAND_LEN;

            size = (int) readUint32(header, cursor);
            cursor += 4;

            if (size > Message.MAX_SIZE || size < 0)
                throw new ProtocolException("Message size too large: " + size);

            // Old clients don't send the checksum.
            checksum = new byte[4];
            // Note that the size read above includes the checksum bytes.
            System.arraycopy(header, cursor, checksum, 0, 4);
        }
    }
}
