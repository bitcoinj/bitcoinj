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
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;

import static com.google.bitcoin.core.Utils.*;

/**
 * Methods to serialize and de-serialize messages to the bitcoin network format as defined in the bitcoin protocol
 * specification at https://en.bitcoin.it/wiki/Protocol_specification
 *
 * To be able to serialize and deserialize new Message subclasses the following criteria needs to be met.
 * <ul>
 *     <li>The proper Class instance needs to be mapped to it's message name in the names variable below</li>
 *     <li>There needs to be a constructor matching: NetworkParameters params, byte[] payload</li>
 *     <li>Message.bitcoinSerializeToStream() needs to be properly subclassed</li>
 * </ul>
 *
 */
public class BitcoinSerializer
{
    private static final Logger log = LoggerFactory.getLogger(BitcoinSerializer.class);
    private static final int COMMAND_LEN = 12;
    
    private NetworkParameters params;
    private boolean usesChecksumming;

    private static Map<Class<? extends Message>, String> names = new HashMap<Class<? extends Message>,String>();

    static {
        names.put(VersionMessage.class, "version");
        names.put(InventoryMessage.class, "inv");
        names.put(Block.class, "block");
        names.put(GetDataMessage.class, "getdata");
        names.put(Transaction.class, "tx");
        names.put(AddressMessage.class, "addr");
        names.put(Ping.class, "ping");
        names.put(VersionAck.class, "verack");
        names.put(GetBlocksMessage.class, "getblocks");
    }

    /**
     * Constructs a BitcoinSerializer with the given behavior.
     *
     * @param params networkParams used to create Messages instances and termining packetMagic
     * @param usesChecksumming set to true if checkums should be included and expected in headers
     */
    public BitcoinSerializer(NetworkParameters params, boolean usesChecksumming) {
        this.params = params;
        this.usesChecksumming = usesChecksumming;
    }

    public void useChecksumming(boolean usesChecksumming) {
        this.usesChecksumming = usesChecksumming;
    }


    /**
     * Writes message to to the output stream.
     */
    public void serialize(Message message, OutputStream out) throws IOException {
        String name = names.get(message.getClass());
        if (name == null) {
            throw new Error("BitcoinSerializer doesn't currently know how to serialize "+ message.getClass());
        }

        byte[] header = new byte[4 + COMMAND_LEN + 4 + (usesChecksumming ? 4 : 0)];

        uint32ToByteArrayBE(params.packetMagic, header, 0);

        // The header array is initialized to zero by Java so we don't have to worry about
        // NULL terminating the string here.
        for (int i = 0; i < name.length() && i < COMMAND_LEN; i++) {
            header[4 + i] = (byte) (name.codePointAt(i) & 0xFF);
        }

        byte[] payload = message.bitcoinSerialize();

        Utils.uint32ToByteArrayLE(payload.length, header, 4 + COMMAND_LEN);

        if (usesChecksumming) {
            byte[] hash = doubleDigest(payload);
            System.arraycopy(hash, 0, header, 4 + COMMAND_LEN + 4, 4);
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
        // A BitCoin protocol message has the following format.
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
        // Now read in the header.
        byte[] header = new byte[COMMAND_LEN + 4 + (usesChecksumming ? 4 : 0)];
        int readCursor = 0;
        while (readCursor < header.length) {
            int bytesRead = in.read(header, readCursor, header.length - readCursor);
            if (bytesRead == -1) {
                // There's no more data to read.
                throw new IOException("Socket is disconnected");
            }
            readCursor += bytesRead;
        }

        int cursor = 0;

        // The command is a NULL terminated string, unless the command fills all twelve bytes
        // in which case the termination is implicit.
        String command;
        int mark = cursor;
        for (; header[cursor] != 0 && cursor - mark < COMMAND_LEN; cursor++);
        byte[] commandBytes = new byte[cursor - mark];
        System.arraycopy(header, mark, commandBytes, 0, cursor - mark);
        try {
            command = new String(commandBytes, "US-ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
        cursor = mark + COMMAND_LEN;

        int size = (int) readUint32(header, cursor);
        cursor += 4;

        if (size > Message.MAX_SIZE)
            throw new ProtocolException("Message size too large: " + size);

        // Old clients don't send the checksum.
        byte[] checksum = new byte[4];
        if (usesChecksumming) {
            // Note that the size read above includes the checksum bytes.
            System.arraycopy(header, cursor, checksum, 0, 4);
            cursor += 4;
        }

        // Now try to read the whole message.
        readCursor = 0;
        byte[] payloadBytes = new byte[size];
        while (readCursor < payloadBytes.length - 1) {
            int bytesRead = in.read(payloadBytes, readCursor, size - readCursor);
            if (bytesRead == -1) {
                throw new IOException("Socket is disconnected");
            }
            readCursor += bytesRead;
        }

        // Verify the checksum.
        if (usesChecksumming) {
            byte[] hash = doubleDigest(payloadBytes);
            if (checksum[0] != hash[0] || checksum[1] != hash[1] ||
                checksum[2] != hash[2] || checksum[3] != hash[3]) {
                throw new ProtocolException("Checksum failed to verify, actual " +
                        bytesToHexString(hash) +
                        " vs " + bytesToHexString(checksum));
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Received {} byte '{}' message: {}", new Object[]{
        		size,
        		command,
        		Utils.bytesToHexString(payloadBytes)
            });
        }

        try {
            return makeMessage(command, payloadBytes);
        } catch (Exception e) {
            throw new ProtocolException("Error deserializing message " + Utils.bytesToHexString(payloadBytes) + "\n", e);
        }

    }

    private Message makeMessage(String command, byte[] payloadBytes) throws ProtocolException {
        // We use an if ladder rather than reflection because reflection is very slow on Android.
        if (command.equals("version")) {
            return new VersionMessage(params, payloadBytes);
        } else if (command.equals("inv")) {
            return new InventoryMessage(params, payloadBytes);
        } else if (command.equals("block")) {
            return new Block(params, payloadBytes);
        } else if (command.equals("getdata")) {
            return new GetDataMessage(params, payloadBytes);
        } else if (command.equals("tx")) {
            return new Transaction(params, payloadBytes);
        } else if (command.equals("addr")) {
            return new AddressMessage(params, payloadBytes);
        } else if (command.equals("ping")) {
            return new Ping();
        } else if (command.equals("verack")) {
            return new VersionAck(params, payloadBytes);
        } else {
            throw new ProtocolException("No support for deserializing message with name " + command);
        }
    }

    private Constructor<? extends Message> makeConstructor(Class<? extends Message> c) {
        Class<?> parTypes[] = new Class<?>[2];
        parTypes[0] = NetworkParameters.class;
        parTypes[1] = byte[].class;

        try {
            return c.getDeclaredConstructor(parTypes);
        } catch (NoSuchMethodException e) {
            return null;
        }

    }


    private void seekPastMagicBytes(InputStream in) throws IOException {
        int magicCursor = 3;  // Which byte of the magic we're looking for currently.
        while (true) {
            int b = in.read();  // Read a byte.
            if (b == -1) {
                // There's no more data to read.
                throw new IOException("Socket is disconnected");
            }
            // We're looking for a run of bytes that is the same as the packet magic but we want to ignore partial
            // magics that aren't complete. So we keep track of where we're up to with magicCursor.
            int expectedByte = 0xFF & (int)(params.packetMagic >>> (magicCursor * 8));
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
}
