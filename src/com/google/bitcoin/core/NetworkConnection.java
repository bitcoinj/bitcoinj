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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;

import static com.google.bitcoin.core.Utils.*;

/**
 * A NetworkConnection handles talking to a remote BitCoin peer at a low level. It understands how to read and write
 * messages off the network, but doesn't asynchronously communicate with the peer or handle the higher level details
 * of the protocol. After constructing a NetworkConnection, use a {@link Peer} to hand off communication to a
 * background thread.
 *
 * Construction is blocking whilst the protocol version is negotiated.
 */
public class NetworkConnection {
    static final int COMMAND_LEN = 12;

    // Message strings.
    static final String MSG_VERSION = "version";
    static final String MSG_INVENTORY = "inv";
    static final String MSG_BLOCK = "block";
    static final String MSG_GETBLOCKS = "getblocks";
    static final String MSG_GETDATA = "getdata";
    static final String MSG_TX = "tx";
    static final String MSG_ADDR = "addr";
    static final String MSG_VERACK = "verack";

    private final Socket socket;
    private final OutputStream out;
    private final InputStream in;
    // The IP address to which we are connecting.
    private InetAddress remoteIp;
    private boolean usesChecksumming;
    private final NetworkParameters params;
    static final private boolean PROTOCOL_LOG = false;

    /**
     * Connect to the given IP address using the port specified as part of the network parameters. Once construction
     * is complete a functioning network channel is set up and running.
     * @param remoteIp IP address to connect to. IPv6 is not currently supported by BitCoin.
     * @param params Defines which network to connect to and details of the protocol.
     * @throws IOException if there is a network related failure.
     * @throws ProtocolException if the version negotiation failed.
     */
    public NetworkConnection(InetAddress remoteIp, NetworkParameters params) throws IOException, ProtocolException {
        this.params = params;
        this.remoteIp = remoteIp;
        socket = new Socket(remoteIp, params.port);
        out = socket.getOutputStream();
        in = socket.getInputStream();

        // When connecting, the remote peer sends us a version message with various bits of
        // useful data in it. We need to know the peer protocol version before we can talk to it.
        VersionMessage ver = (VersionMessage) readMessage();
        // Now it's our turn ...
        writeMessage(MSG_VERSION, new VersionMessage(params));
        // Send an ACK message stating we accept the peers protocol version.
        writeMessage(MSG_VERACK, new byte[] {});
        // And get one back ...
        readMessage();
        // Switch to the new protocol version.
        int peerVersion = (int) ver.clientVersion;
        usesChecksumming = peerVersion >= 209;
        // Handshake is done!
    }

    /**
     * Sends a "ping" message to the remote node. The protocol doesn't presently use this feature much.
     * @throws IOException
     */
    public void ping() throws IOException {
        writeMessage("ping", new byte[] {});
    }

    /**
     * Shuts down the network socket. Note that there's no way to wait for a socket to be fully flushed out to the
     * wire, so if you call this immediately after sending a message it might not get sent.
     */
    public void shutdown() throws IOException {
        socket.shutdownOutput();
        socket.shutdownInput();
        socket.close();
    }

    @Override
    public String toString() {
        return "[" + remoteIp.getHostAddress() + "]:" + params.port + " (" + (socket.isConnected() ? "connected" :
                "disconnected") + ")";
    }

    /**
     * Reads a network message from the wire, blocking until the message is fully received.
     *
     * @return An instance of a Message subclass
     * @throws ProtocolException if the message is badly formatted, failed checksum or there was a TCP failure.
     */
    public Message readMessage() throws IOException, ProtocolException {
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
        byte[] header = new byte[4 + COMMAND_LEN + 4 + (usesChecksumming ? 4 : 0)];
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
        long magic = Utils.readUint32BE(header, 0);
        cursor += 4;
        if (magic != params.packetMagic)
            throw new ProtocolException(String.format("Unexpected magic number: 0x%x", magic));

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

        if (PROTOCOL_LOG)
            LOG("Received " + size + " byte '" + command + "' command");

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
                throw new ProtocolException("Socket disconnected half way through a message");
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

        try {
            Message message = null;
            if (command.equals(MSG_VERSION))
                message = new VersionMessage(params, payloadBytes);
            else if (command.equals(MSG_INVENTORY))
                message = new InventoryMessage(params, payloadBytes);
            else if (command.equals(MSG_BLOCK))
                message = new Block(params, payloadBytes);
            else if (command.equals(MSG_GETDATA))
                message = new GetDataMessage(params, payloadBytes);
            else if (command.equals(MSG_TX))
                message = new Transaction(params, payloadBytes);
            else if (command.equals(MSG_ADDR))
                message = new AddressMessage(params, payloadBytes);
            else
                message = new UnknownMessage(params, command, payloadBytes);
            return message;
        } catch (Exception e) {
            throw new ProtocolException("Error deserializing message " + Utils.bytesToHexString(payloadBytes) + "\n", e);
        }
    }

    private void writeMessage(String name,  byte[] payload) throws IOException {
        byte[] header = new byte[4 + COMMAND_LEN + 4 + (usesChecksumming ? 4 : 0)];

        uint32ToByteArrayBE(params.packetMagic, header, 0);

        // The header array is initialized to zero by Java so we don't have to worry about
        // NULL terminating the string here.
        for (int i = 0; i < name.length() && i < COMMAND_LEN; i++) {
            header[4 + i] = (byte) (name.codePointAt(i) & 0xFF);
        }

        Utils.uint32ToByteArrayLE(payload.length, header, 4 + COMMAND_LEN);

        if (usesChecksumming) {
            byte[] hash = doubleDigest(payload);
            System.arraycopy(hash, 0, header, 4 + COMMAND_LEN + 4, 4);
        }

        if (PROTOCOL_LOG)
            LOG("Sending " + name + " message: " + bytesToHexString(payload));

        // Another writeMessage call may be running concurrently.
        synchronized (out) {
            out.write(header);
            out.write(payload);
        }
    }

    /**
     * Writes the given message out over the network using the protocol tag. For a Transaction
     * this should be "tx" for example. It's safe to call this from multiple threads simultaneously,
     * the actual writing will be serialized.
     *
     * @throws IOException
     */
    public void writeMessage(String tag,  Message message) throws IOException {
        // TODO: Requiring "tag" here is redundant, the message object should know its own protocol tag.
        writeMessage(tag, message.bitcoinSerialize());
    }
}
