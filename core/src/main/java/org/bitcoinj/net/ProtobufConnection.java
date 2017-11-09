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

package org.bitcoinj.net;

import org.bitcoinj.core.Utils;
import org.bitcoinj.utils.Threading;
import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.concurrent.GuardedBy;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * <p>A handler which is used in {@link NioServer} and {@link NioClient} to split up incoming data streams
 * into protobufs and provide an interface for writing protobufs to the connections.</p>
 *
 * <p>Messages are encoded with a 4-byte signed integer (big endian) prefix to indicate their length followed by the
 * serialized protobuf</p>
 *
 * <p>(Used to be called ProtobufParser)</p>
 */
public class ProtobufConnection<MessageType extends MessageLite> extends AbstractTimeoutHandler implements StreamConnection {
    private static final Logger log = LoggerFactory.getLogger(ProtobufConnection.class);

    /**
     * An interface which can be implemented to handle callbacks as new messages are generated and socket events occur.
     * @param <MessageType> The protobuf type which is used on this socket.
     *                      This <b>MUST</b> match the MessageType used in the parent {@link ProtobufConnection}
     */
    public interface Listener<MessageType extends MessageLite> {
        /** Called when a new protobuf is received from the remote side. */
        void messageReceived(ProtobufConnection<MessageType> handler, MessageType msg);
        /** Called when the connection is opened and available for writing data to. */
        void connectionOpen(ProtobufConnection<MessageType> handler);
        /** Called when the connection is closed and no more data should be provided. */
        void connectionClosed(ProtobufConnection<MessageType> handler);
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
    @GuardedBy("lock") private int messageBytesOffset = 0;
    @GuardedBy("lock") private byte[] messageBytes;
    private final ReentrantLock lock = Threading.lock("ProtobufConnection");

    @VisibleForTesting final AtomicReference<MessageWriteTarget> writeTarget = new AtomicReference<>();

    /**
     * Creates a new protobuf handler.
     *
     * @param handler The callback listener
     * @param prototype The default instance of the message type used in both directions of this channel.
     *                  This should be the return value from {@link MessageLite#getDefaultInstanceForType()}
     * @param maxMessageSize The maximum message size (not including the 4-byte length prefix).
     *                       Note that this has an upper bound of {@link Integer#MAX_VALUE} - 4
     * @param timeoutMillis The timeout between messages before the connection is automatically closed. Only enabled
     *                      after the connection is established.
     */
    public ProtobufConnection(Listener<MessageType> handler, MessageType prototype, int maxMessageSize, int timeoutMillis) {
        this.handler = handler;
        this.prototype = prototype;
        this.maxMessageSize = Math.min(maxMessageSize, Integer.MAX_VALUE - 4);
        setTimeoutEnabled(false);
        setSocketTimeout(timeoutMillis);
    }

    @Override
    public void setWriteTarget(MessageWriteTarget writeTarget) {
        // Only allow it to be set once.
        checkState(this.writeTarget.getAndSet(checkNotNull(writeTarget)) == null);
    }

    @Override
    public int getMaxMessageSize() {
        return maxMessageSize;
    }

    /**
     * Closes this connection, eventually triggering a {@link ProtobufConnection.Listener#connectionClosed()} event.
     */
    public void closeConnection() {
        this.writeTarget.get().closeConnection();
    }

    @Override
    protected void timeoutOccurred() {
        log.warn("Timeout occurred for " + handler);
        closeConnection();
    }

    // Deserializes and provides a listener event (buff must not have the length prefix in it)
    // Does set the buffers's position to its limit
    @SuppressWarnings("unchecked")
    // The warning 'unchecked cast' being suppressed here comes from the build() formally returning
    // a MessageLite-derived class that cannot be statically guaranteed to be the MessageType.
    private void deserializeMessage(ByteBuffer buff) throws Exception {
        MessageType msg = (MessageType) prototype.newBuilderForType().mergeFrom(ByteString.copyFrom(buff)).build();
        resetTimeout();
        handler.messageReceived(this, msg);
    }

    @Override
    public int receiveBytes(ByteBuffer buff) throws Exception {
        lock.lock();
        try {
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
                        return bytesToGet + receiveBytes(buff);
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
                return len + 4 + receiveBytes(buff);
            else
                return len + 4;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void connectionClosed() {
        handler.connectionClosed(this);
    }

    @Override
    public void connectionOpened() {
        setTimeoutEnabled(true);
        handler.connectionOpen(this);
    }

    /**
     * <p>Writes the given message to the other side of the connection, prefixing it with the proper 4-byte prefix.</p>
     *
     * <p>Provides a write-order guarantee.</p>
     *
     * @throws IllegalStateException If the encoded message is larger than the maximum message size.
     */
    public void write(MessageType msg) throws IllegalStateException {
        byte[] messageBytes = msg.toByteArray();
        checkState(messageBytes.length <= maxMessageSize);
        byte[] messageLength = new byte[4];
        Utils.uint32ToByteArrayBE(messageBytes.length, messageLength, 0);
        try {
            MessageWriteTarget target = writeTarget.get();
            target.writeBytes(messageLength);
            target.writeBytes(messageBytes);
        } catch (IOException e) {
            closeConnection();
        }
    }
}
