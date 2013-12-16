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

package com.google.bitcoin.core;

import com.google.bitcoin.net.AbstractTimeoutHandler;
import com.google.bitcoin.net.MessageWriteTarget;
import com.google.bitcoin.net.StreamParser;
import com.google.bitcoin.utils.Threading;
import com.google.common.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.channels.NotYetConnectedException;
import java.util.concurrent.locks.Lock;

import static com.google.common.base.Preconditions.*;

/**
 * Handles high-level message (de)serialization for peers, acting as the bridge between the
 * {@link com.google.bitcoin.net} classes and {@link Peer}.
 */
public abstract class PeerSocketHandler extends AbstractTimeoutHandler implements StreamParser {
    private static final Logger log = LoggerFactory.getLogger(PeerSocketHandler.class);

    private final BitcoinSerializer serializer;
    protected PeerAddress peerAddress;
    // If we close() before we know our writeTarget, set this to true to call writeTarget.closeConnection() right away.
    private boolean closePending = false;
    // writeTarget will be thread-safe, and may call into PeerGroup, which calls us, so we should call it unlocked
    @VisibleForTesting MessageWriteTarget writeTarget = null;

    // The ByteBuffers passed to us from the writeTarget are static in size, and usually smaller than some messages we
    // will receive. For SPV clients, this should be rare (ie we're mostly dealing with small transactions), but for
    // messages which are larger than the read buffer, we have to keep a temporary buffer with its bytes.
    private byte[] largeReadBuffer;
    private int largeReadBufferPos;
    private BitcoinSerializer.BitcoinPacketHeader header;

    private Lock lock = Threading.lock("PeerSocketHandler");

    public PeerSocketHandler(NetworkParameters params, InetSocketAddress remoteIp) {
        serializer = new BitcoinSerializer(checkNotNull(params));
        this.peerAddress = new PeerAddress(remoteIp);
    }

    public PeerSocketHandler(NetworkParameters params, PeerAddress peerAddress) {
        serializer = new BitcoinSerializer(checkNotNull(params));
        this.peerAddress = checkNotNull(peerAddress);
    }

    /**
     * Sends the given message to the peer. Due to the asynchronousness of network programming, there is no guarantee
     * the peer will have received it. Throws NotYetConnectedException if we are not yet connected to the remote peer.
     * TODO: Maybe use something other than the unchecked NotYetConnectedException here
     */
    public void sendMessage(Message message) throws NotYetConnectedException {
        lock.lock();
        try {
            if (writeTarget == null)
                throw new NotYetConnectedException();
        } finally {
            lock.unlock();
        }
        // TODO: Some round-tripping could be avoided here
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            serializer.serialize(message, out);
            writeTarget.writeBytes(out.toByteArray());
        } catch (IOException e) {
            exceptionCaught(e);
        }
    }

    /**
     * Closes the connection to the peer if one exists, or immediately closes the connection as soon as it opens
     */
    public void close() {
        lock.lock();
        try {
            if (writeTarget == null) {
                closePending = true;
                return;
            }
        } finally {
            lock.unlock();
        }
        writeTarget.closeConnection();
    }

    @Override
    protected void timeoutOccurred() {
        log.info("{}: Timed out", getAddress());
        close();
    }

    /**
     * Called every time a message is received from the network
     */
    protected abstract void processMessage(Message m) throws Exception;

    @Override
    public int receiveBytes(ByteBuffer buff) {
        checkArgument(buff.position() == 0 &&
                buff.capacity() >= BitcoinSerializer.BitcoinPacketHeader.HEADER_LENGTH + 4);
        try {
            // Repeatedly try to deserialize messages until we hit a BufferUnderflowException
            for (int i = 0; true; i++) {
                // If we are in the middle of reading a message, try to fill that one first, before we expect another
                if (largeReadBuffer != null) {
                    // This can only happen in the first iteration
                    checkState(i == 0);
                    // Read new bytes into the largeReadBuffer
                    int bytesToGet = Math.min(buff.remaining(), largeReadBuffer.length - largeReadBufferPos);
                    buff.get(largeReadBuffer, largeReadBufferPos, bytesToGet);
                    largeReadBufferPos += bytesToGet;
                    // Check the largeReadBuffer's status
                    if (largeReadBufferPos == largeReadBuffer.length) {
                        // ...processing a message if one is available
                        processMessage(serializer.deserializePayload(header, ByteBuffer.wrap(largeReadBuffer)));
                        largeReadBuffer = null;
                        header = null;
                    } else // ...or just returning if we don't have enough bytes yet
                        return buff.position();
                }
                // Now try to deserialize any messages left in buff
                Message message;
                int preSerializePosition = buff.position();
                try {
                    message = serializer.deserialize(buff);
                } catch (BufferUnderflowException e) {
                    // If we went through the whole buffer without a full message, we need to use the largeReadBuffer
                    if (i == 0 && buff.limit() == buff.capacity()) {
                        // ...so reposition the buffer to 0 and read the next message header
                        buff.position(0);
                        try {
                            serializer.seekPastMagicBytes(buff);
                            header = serializer.deserializeHeader(buff);
                            // Initialize the largeReadBuffer with the next message's size and fill it with any bytes
                            // left in buff
                            largeReadBuffer = new byte[header.size];
                            largeReadBufferPos = buff.remaining();
                            buff.get(largeReadBuffer, 0, largeReadBufferPos);
                        } catch (BufferUnderflowException e1) {
                            // If we went through a whole buffer's worth of bytes without getting a header, give up
                            // In cases where the buff is just really small, we could create a second largeReadBuffer
                            // that we use to deserialize the magic+header, but that is rather complicated when the buff
                            // should probably be at least that big anyway (for efficiency)
                            throw new ProtocolException("No magic bytes+header after reading " + buff.capacity() + " bytes");
                        }
                    } else {
                        // Reposition the buffer to its original position, which saves us from skipping messages by
                        // seeking past part of the magic bytes before all of them are in the buffer
                        buff.position(preSerializePosition);
                    }
                    return buff.position();
                }
                // Process our freshly deserialized message
                processMessage(message);
            }
        } catch (Exception e) {
            exceptionCaught(e);
            return -1; // Returning -1 also throws an IllegalStateException upstream and kills the connection
        }
    }

    /**
     * Sets the {@link MessageWriteTarget} used to write messages to the peer. This should almost never be called, it is
     * called automatically by {@link com.google.bitcoin.net.NioClient} or
     * {@link com.google.bitcoin.net.NioClientManager} once the socket finishes initialization.
     */
    @Override
    public void setWriteTarget(MessageWriteTarget writeTarget) {
        checkArgument(writeTarget != null);
        lock.lock();
        boolean closeNow = false;
        try {
            checkArgument(this.writeTarget == null);
            closeNow = closePending;
            this.writeTarget = writeTarget;
        } finally {
            lock.unlock();
        }
        if (closeNow)
            writeTarget.closeConnection();
    }

    @Override
    public int getMaxMessageSize() {
        return Message.MAX_SIZE;
    }

    /**
     * @return the IP address and port of peer.
     */
    public PeerAddress getAddress() {
        return peerAddress;
    }

    /** Catch any exceptions, logging them and then closing the channel. */
    private void exceptionCaught(Exception e) {
        PeerAddress addr = getAddress();
        String s = addr == null ? "?" : addr.toString();
        if (e instanceof ConnectException || e instanceof IOException) {
            // Short message for network errors
            log.info(s + " - " + e.getMessage());
        } else {
            log.warn(s + " - ", e);
            Thread.UncaughtExceptionHandler handler = Threading.uncaughtExceptionHandler;
            if (handler != null)
                handler.uncaughtException(Thread.currentThread(), e);
        }

        close();
    }
}
