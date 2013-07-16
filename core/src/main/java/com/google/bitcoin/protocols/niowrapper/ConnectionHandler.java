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

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.concurrent.locks.ReentrantLock;

import com.google.bitcoin.utils.Threading;
import org.slf4j.LoggerFactory;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
* A simple connection handler which handles all the business logic of a connection
*/
class ConnectionHandler implements MessageWriteTarget {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(ConnectionHandler.class);

    private static final int BUFFER_SIZE_LOWER_BOUND = 4096;
    private static final int BUFFER_SIZE_UPPER_BOUND = 65536;

    private final ReentrantLock lock = Threading.lock("nioConnectionHandler");
    private final ByteBuffer dbuf;
    private final SocketChannel channel;
    final StreamParser parser;
    private boolean closeCalled = false;

    ConnectionHandler(StreamParserFactory parserFactory, SocketChannel channel) throws IOException {
        this.channel = checkNotNull(channel);
        StreamParser newParser = parserFactory.getNewParser(channel.socket().getInetAddress(), channel.socket().getPort());
        if (newParser == null) {
            closeConnection();
            throw new IOException("Parser factory.getNewParser returned null");
        }
        this.parser = newParser;
        dbuf = ByteBuffer.allocateDirect(Math.min(Math.max(parser.getMaxMessageSize(), BUFFER_SIZE_LOWER_BOUND), BUFFER_SIZE_UPPER_BOUND));
        newParser.setWriteTarget(this);
    }

    @Override
    public void writeBytes(byte[] message) throws IOException {
        lock.lock();
        try {
            if (channel.write(ByteBuffer.wrap(message)) != message.length)
                throw new IOException("Couldn't write all of message to socket");
        } catch (IOException e) {
            log.error("Error writing message to connection, closing connection", e);
            closeConnection();
            throw e;
        } finally {
            lock.unlock();
        }
    }

    @Override
    public void closeConnection() {
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
        if (callClosed)
            parser.connectionClosed();
    }

    // Handle a SelectionKey which was selected
    static void handleKey(SelectionKey key) throws IOException {
        ConnectionHandler handler = ((ConnectionHandler)key.attachment());
        try {
            if (!key.isValid() && handler != null)
                handler.closeConnection(); // Key has been cancelled, make sure the socket gets closed
            else if (handler != null && key.isReadable()) {
                // Do a socket read and invoke the parser's receiveBytes message
                int read = handler.channel.read(handler.dbuf);
                if (read == 0)
                    return; // Should probably never happen, but just in case it actually can just return 0
                else if (read == -1) { // Socket was closed
                    key.cancel();
                    handler.closeConnection();
                    return;
                }
                // "flip" the buffer - setting the limit to the current position and setting position to 0
                handler.dbuf.flip();
                // Use parser.receiveBytes's return value as a check that it stopped reading at the right location
                int bytesConsumed = handler.parser.receiveBytes(handler.dbuf);
                checkState(handler.dbuf.position() == bytesConsumed);
                // Now drop the bytes which were read by compacting dbuf (resetting limit and keeping relative
                // position)
                handler.dbuf.compact();
            }
        } catch (Exception e) {
            // This can happen eg if the channel closes while the tread is about to get killed
            // (ClosedByInterruptException), or if parser.parser.receiveBytes throws something
            log.error("Error handling SelectionKey", e);
            if (handler != null)
                handler.closeConnection();
        }
    }
}
