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

import com.google.common.base.Throwables;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import org.bitcoinj.core.Message;
import org.bitcoinj.utils.Threading;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.annotation.concurrent.GuardedBy;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

// TODO: The locking in all this class is horrible and not really necessary. We should just run all network stuff on one thread.

/**
 * A simple NIO MessageWriteTarget which handles all the business logic of a connection (reading+writing bytes).
 * Used only by the NioClient and NioServer classes
 */
class ConnectionHandler implements MessageWriteTarget {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(ConnectionHandler.class);

    private static final int BUFFER_SIZE_LOWER_BOUND = 4096;
    private static final int BUFFER_SIZE_UPPER_BOUND = 65536;

    private static final int OUTBOUND_BUFFER_BYTE_COUNT = Message.MAX_SIZE + 24; // 24 byte message header

    // We lock when touching local flags and when writing data, but NEVER when calling any methods which leave this
    // class into non-Java classes.
    private final ReentrantLock lock = Threading.lock("nioConnectionHandler");
    @GuardedBy("lock") private final ByteBuffer readBuff;
    @GuardedBy("lock") private final SocketChannel channel;
    @GuardedBy("lock") private final SelectionKey key;
    @GuardedBy("lock") StreamConnection connection;
    @GuardedBy("lock") private boolean closeCalled = false;

    @GuardedBy("lock") private long bytesToWriteRemaining = 0;
    @GuardedBy("lock") private final LinkedList<BytesAndFuture> bytesToWrite = new LinkedList<>();

    private static class BytesAndFuture {
        public final ByteBuffer bytes;
        public final SettableFuture future;

        public BytesAndFuture(ByteBuffer bytes, SettableFuture future) {
            this.bytes = bytes;
            this.future = future;
        }
    }

    private Set<ConnectionHandler> connectedHandlers;

    public ConnectionHandler(StreamConnectionFactory connectionFactory, SelectionKey key) throws IOException {
        this(connectionFactory.getNewConnection(((SocketChannel) key.channel()).socket().getInetAddress(), ((SocketChannel) key.channel()).socket().getPort()), key);
        if (connection == null)
            throw new IOException("Parser factory.getNewConnection returned null");
    }

    private ConnectionHandler(@Nullable StreamConnection connection, SelectionKey key) {
        this.key = key;
        this.channel = checkNotNull(((SocketChannel)key.channel()));
        if (connection == null) {
            readBuff = null;
            return;
        }
        this.connection = connection;
        readBuff = ByteBuffer.allocateDirect(Math.min(Math.max(connection.getMaxMessageSize(), BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND));
        connection.setWriteTarget(this); // May callback into us (eg closeConnection() now)
        connectedHandlers = null;
    }

    public ConnectionHandler(StreamConnection connection, SelectionKey key, Set<ConnectionHandler> connectedHandlers) {
        this(checkNotNull(connection), key);

        // closeConnection() may have already happened because we invoked the other c'tor above, which called
        // connection.setWriteTarget which might have re-entered already. In this case we shouldn't add ourselves
        // to the connectedHandlers set.
        lock.lock();
        try {
            this.connectedHandlers = connectedHandlers;
            if (!closeCalled)
                checkState(this.connectedHandlers.add(this));
        } finally {
            lock.unlock();
        }
    }

    @GuardedBy("lock")
    private void setWriteOps() {
        // Make sure we are registered to get updated when writing is available again
        key.interestOps(key.interestOps() | SelectionKey.OP_WRITE);
        // Refresh the selector to make sure it gets the new interestOps
        key.selector().wakeup();
    }

    // Tries to write any outstanding write bytes, runs in any thread (possibly unlocked)
    private void tryWriteBytes() throws IOException {
        lock.lock();
        try {
            // Iterate through the outbound ByteBuff queue, pushing as much as possible into the OS' network buffer.
            Iterator<BytesAndFuture> iterator = bytesToWrite.iterator();
            while (iterator.hasNext()) {
                BytesAndFuture bytesAndFuture = iterator.next();
                bytesToWriteRemaining -= channel.write(bytesAndFuture.bytes);
                if (!bytesAndFuture.bytes.hasRemaining()) {
                    iterator.remove();
                    bytesAndFuture.future.set(null);
                } else {
                    setWriteOps();
                    break;
                }
            }
            // If we are done writing, clear the OP_WRITE interestOps
            if (bytesToWrite.isEmpty())
                key.interestOps(key.interestOps() & ~SelectionKey.OP_WRITE);
            // Don't bother waking up the selector here, since we're just removing an op, not adding
        } finally {
            lock.unlock();
        }
    }

    @Override
    public ListenableFuture writeBytes(byte[] message) throws IOException {
        boolean andUnlock = true;
        lock.lock();
        try {
            // Network buffers are not unlimited (and are often smaller than some messages we may wish to send), and
            // thus we have to buffer outbound messages sometimes. To do this, we use a queue of ByteBuffers and just
            // append to it when we want to send a message. We then let tryWriteBytes() either send the message or
            // register our SelectionKey to wakeup when we have free outbound buffer space available.

            if (bytesToWriteRemaining + message.length > OUTBOUND_BUFFER_BYTE_COUNT)
                throw new IOException("Outbound buffer overflowed");
            // Just dump the message onto the write buffer and call tryWriteBytes
            // TODO: Kill the needless message duplication when the write completes right away
            final SettableFuture<Object> future = SettableFuture.create();
            bytesToWrite.offer(new BytesAndFuture(ByteBuffer.wrap(Arrays.copyOf(message, message.length)), future));
            bytesToWriteRemaining += message.length;
            setWriteOps();
            return future;
        } catch (IOException e) {
            lock.unlock();
            andUnlock = false;
            log.warn("Error writing message to connection, closing connection", e);
            closeConnection();
            throw e;
        } catch (CancelledKeyException e) {
            lock.unlock();
            andUnlock = false;
            log.warn("Error writing message to connection, closing connection", e);
            closeConnection();
            throw new IOException(e);
        } finally {
            if (andUnlock)
                lock.unlock();
        }
    }

    // May NOT be called with lock held
    @Override
    public void closeConnection() {
        checkState(!lock.isHeldByCurrentThread());
        try {
            channel.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        connectionClosed();
    }

    private void connectionClosed() {
        boolean callClosed = false;
        lock.lock();
        try {
            callClosed = !closeCalled;
            closeCalled = true;
        } finally {
            lock.unlock();
        }
        if (callClosed) {
            checkState(connectedHandlers == null || connectedHandlers.remove(this));
            connection.connectionClosed();
        }
    }

    // Handle a SelectionKey which was selected
    // Runs unlocked as the caller is single-threaded (or if not, should enforce that handleKey is only called
    // atomically for a given ConnectionHandler)
    public static void handleKey(SelectionKey key) {
        ConnectionHandler handler = ((ConnectionHandler)key.attachment());
        try {
            if (handler == null)
                return;
            if (!key.isValid()) {
                handler.closeConnection(); // Key has been cancelled, make sure the socket gets closed
                return;
            }
            if (key.isReadable()) {
                // Do a socket read and invoke the connection's receiveBytes message
                int read = handler.channel.read(handler.readBuff);
                if (read == 0)
                    return; // Was probably waiting on a write
                else if (read == -1) { // Socket was closed
                    key.cancel();
                    handler.closeConnection();
                    return;
                }
                // "flip" the buffer - setting the limit to the current position and setting position to 0
                handler.readBuff.flip();
                // Use connection.receiveBytes's return value as a check that it stopped reading at the right location
                int bytesConsumed = checkNotNull(handler.connection).receiveBytes(handler.readBuff);
                checkState(handler.readBuff.position() == bytesConsumed);
                // Now drop the bytes which were read by compacting readBuff (resetting limit and keeping relative
                // position)
                handler.readBuff.compact();
            }
            if (key.isWritable())
                handler.tryWriteBytes();
        } catch (Exception e) {
            // This can happen eg if the channel closes while the thread is about to get killed
            // (ClosedByInterruptException), or if handler.connection.receiveBytes throws something
            Throwable t = Throwables.getRootCause(e);
            log.warn("Error handling SelectionKey: {} {}", t.getClass().getName(), t.getMessage() != null ? t.getMessage() : "", e);
            handler.closeConnection();
        }
    }
}
