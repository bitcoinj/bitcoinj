/*
 * Copyright 2013 Google Inc.
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

package com.google.bitcoin.protocols.niowrapper;

import com.google.bitcoin.core.Utils;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Timer;
import java.util.TimerTask;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * <p>A handler which is used in {@link ProtobufServer} and {@link ProtobufClient} to split up incoming data streams
 * into protobufs and provide an interface for writing protobufs to the connections.</p>
 *
 * <p>Messages are encoded with a 4-byte signed integer (big endian) prefix to indicate their length followed by the
 * serialized protobuf</p>
 */
public class ProtobufParser<MessageType extends MessageLite> {
    /**
     * An interface which can be implemented to handle callbacks as new messages are generated and socket events occur.
     * @param <MessageType> The protobuf type which is used on this socket.
     *                      This <b>MUST</b> match the MessageType used in the parent {@link ProtobufParser}
     */
    public interface Listener<MessageType extends MessageLite> {
        /** Called when a new protobuf is received from the remote side. */
        public void messageReceived(ProtobufParser<MessageType> handler, MessageType msg);
        /** Called when the connection is opened and available for writing data to. */
        public void connectionOpen(ProtobufParser<MessageType> handler);
        /** Called when the connection is closed and no more data should be provided. */
        public void connectionClosed(ProtobufParser<MessageType> handler);
    }

    // The callback listener
    private final Listener<MessageType> handler;
    // The prototype which is used to deserialize messages
    private final MessageLite prototype;

    // The maximum message size (NOT INCLUDING LENGTH PREFIX)
    final int maxMessageSize;

    // A temporary buffer used when the message size is larger than the buffer being used by the network code
    // Because the networking code uses a constant size buffer and we want to allow for very large message sizes, we use
    // a smaller network buffer per client and only allocate more memory when we need it to deserialize large messages.
    // Though this is not in of itself a DoS protection, it allows for handling more legitimate clients per server and
    // attacking clients can be made to timeout/get blocked if they are sending crap to fill buffers.
    private int messageBytesOffset = 0;
    private byte[] messageBytes;

    private MessageWriteTarget writeTarget;

    // TimerTask and timeout value which are added to a timer to kill the connection on timeout
    private TimerTask timeoutTask;
    private long timeoutMillis;

    // A timer which manages expiring connections as their timeouts occur (if configured).
    private static final Timer timeoutTimer = new Timer("ProtobufParser timeouts", true);

    /**
     * Creates a new protobuf handler.
     *
     * @param handler The callback listener
     * @param prototype The default instance of the message type used in both directions of this channel.
     *                  This should be the return value from {@link MessageType#getDefaultInstanceForType()}
     * @param maxMessageSize The maximum message size (not including the 4-byte length prefix).
     *                       Note that this has an upper bound of {@link Integer#MAX_VALUE} - 4
     * @param timeoutMillis The timeout between messages before the connection is automatically closed. Only enabled
     *                      after the connection is established.
     */
    public ProtobufParser(Listener<MessageType> handler, MessageType prototype, int maxMessageSize, int timeoutMillis) {
        this.handler = handler;
        this.prototype = prototype;
        this.timeoutMillis = timeoutMillis;
        this.maxMessageSize = Math.min(maxMessageSize, Integer.MAX_VALUE - 4);
    }

    // Sets the upstream write channel
    synchronized void setWriteTarget(MessageWriteTarget writeTarget) {
        checkState(this.writeTarget == null);
        this.writeTarget = checkNotNull(writeTarget);
    }

    /**
     * Closes this connection, eventually triggering a {@link ProtobufParser.Listener#connectionClosed()} event.
     */
    public synchronized void closeConnection() {
        this.writeTarget.closeConnection();
    }

    // Deserializes and provides a listener event (buff must not have the length prefix in it)
    // Does set the buffers's position to its limit
    private void deserializeMessage(ByteBuffer buff) throws Exception {
        MessageType msg = (MessageType) prototype.newBuilderForType().mergeFrom(ByteString.copyFrom(buff)).build();
        resetTimeout();
        handler.messageReceived(this, msg);
    }

    /**
     * Called when new bytes are available from the remote end.
     * * buff will start with its limit set to the position we can read to and its position set to the location we will
     *   start reading at
     * * May read more than one message (recursively) if there are enough bytes available
     * * Uses messageBytes/messageBytesOffset to store message which are larger (incl their length prefix) than buff's
     *   capacity(), ie it is up to this method to ensure we dont run out of buffer space to decode the next message.
     * * buff will end with its limit the same as it was previously, and its position set to the position up to which
     *   bytes have been read (the same as its return value)
     * @return The amount of bytes consumed which should not be provided again
     */
    synchronized int receive(ByteBuffer buff) throws Exception {
        if (messageBytes != null) {
            // Just keep filling up the currently being worked on message
            int bytesToGet = Math.min(messageBytes.length - messageBytesOffset, buff.remaining());
            buff.get(messageBytes, messageBytesOffset, bytesToGet);
            messageBytesOffset += bytesToGet;
            if (messageBytesOffset == messageBytes.length) {
                // Filled up our buffer, decode the message
                deserializeMessage(ByteBuffer.wrap(messageBytes));
                messageBytes = null;
                if (buff.hasRemaining())
                    return bytesToGet + receive(buff);
            }
            return bytesToGet;
        }

        // If we cant read the length prefix yet, give up
        if (buff.remaining() < 4)
            return 0;

        // Read one integer in big endian
        buff.order(ByteOrder.BIG_ENDIAN);
        final int len = buff.getInt();

        // If length is larger than the maximum message size (or is negative/overflows) throw an exception and close the
        // connection
        if (len > maxMessageSize || len + 4 < 4)
            throw new IllegalStateException("Message too large or length underflowed");

        // If the buffer's capacity is less than the next messages length + 4 (length prefix), we must use messageBytes
        // as a temporary buffer to store the message
        if (buff.capacity() < len + 4) {
            messageBytes = new byte[len];
            // Now copy all remaining bytes into the new buffer, set messageBytesOffset and tell the caller how many
            // bytes we consumed
            int bytesToRead = buff.remaining();
            buff.get(messageBytes, 0, bytesToRead);
            messageBytesOffset = bytesToRead;
            return bytesToRead + 4;
        }

        if (buff.remaining() < len) {
            // Wait until the whole message is available in the buffer
            buff.position(buff.position() - 4); // Make sure the buffer's position is right at the end
            return 0;
        }

        // Temporarily limit the buffer to the size of the message so that the protobuf decode doesn't get messed up
        int limit = buff.limit();
        buff.limit(buff.position() + len);
        deserializeMessage(buff);
        checkState(buff.remaining() == 0);
        buff.limit(limit); // Reset the limit in case we have to recurse

        // If there are still bytes remaining, see if we can pull out another message since we won't get called again
        if (buff.hasRemaining())
            return len + 4 + receive(buff);
        else
            return len + 4;
    }

    /** Called by the upstream connection manager if this connection closes */
    void connectionClosed() {
        handler.connectionClosed(this);
    }

    /** Called by the upstream connection manager when this connection is open */
    void connectionOpen()  {
        resetTimeout();
        handler.connectionOpen(this);
    }

    /**
     * <p>Writes the given message to the other side of the connection, prefixing it with the proper 4-byte prefix.</p>
     *
     * <p>Provides a write-order guarantee.</p>
     *
     * @throws IllegalStateException If the encoded message is larger than the maximum message size.
     */
    public synchronized void write(MessageType msg) throws IllegalStateException {
        byte[] messageBytes = msg.toByteArray();
        checkState(messageBytes.length <= maxMessageSize);
        byte[] messageLength = new byte[4];
        Utils.uint32ToByteArrayBE(messageBytes.length, messageLength, 0);
        writeTarget.writeBytes(messageLength);
        writeTarget.writeBytes(messageBytes);
    }

    /**
     * <p>Sets the receive timeout to the given number of milliseconds, automatically killing the connection if no
     * messages are received for this long</p>
     *
     * <p>A timeout of 0 is interpreted as no timeout</p>
     */
    public synchronized void setSocketTimeout(int timeoutMillis) {
        this.timeoutMillis = timeoutMillis;
        resetTimeout();
    }

    private synchronized void resetTimeout() {
        if (timeoutTask != null)
            timeoutTask.cancel();
        if (timeoutMillis == 0)
            return;
        timeoutTask = new TimerTask() {
            @Override
            public void run() {
                closeConnection();
            }
        };
        timeoutTimer.schedule(timeoutTask, timeoutMillis);
    }
}
