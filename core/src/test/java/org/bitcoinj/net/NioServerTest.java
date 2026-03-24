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

import com.google.common.util.concurrent.Service;
import org.junit.Test;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Reproducer for intermittent BindException in integration tests.
 *
 * When a NioServer's run() method exits due to an unchecked exception,
 * the Guava Service enters FAILED state and awaitTerminated() throws
 * IllegalStateException. In TestWithNetworkConnections.stopPeerServers(),
 * this aborts the teardown loop, leaving remaining servers' ports bound.
 */
public class NioServerTest {

    private static final StreamConnectionFactory DUMMY_FACTORY = (inetAddress, port) -> new StreamConnection() {
        @Override public void connectionOpened() {}
        @Override public void connectionClosed() {}
        @Override public int receiveBytes(ByteBuffer buff) { return 0; }
        @Override public void setWriteTarget(MessageWriteTarget writeTarget) {}
        @Override public int getMaxMessageSize() { return 1000; }
    };

    private static int getPort(NioServer server) {
        ServerSocketChannel ch = (ServerSocketChannel)
                server.selector.keys().iterator().next().channel();
        return ch.socket().getLocalPort();
    }

    /**
     * Reproduces the intermittent BindException cascade.
     *
     * Simulates what happens in TestWithNetworkConnections when one NioServer
     * enters FAILED state: stopPeerServers() calls awaitTerminated() which
     * throws IllegalStateException, aborting the teardown loop and leaving the
     * second server's port bound. A subsequent bind to that port then fails.
     *
     * This test demonstrates that awaitTerminated() throws on the current code.
     * A correct fix should make awaitTerminated() NOT throw, which would allow
     * the teardown loop to complete normally.
     */
    @Test
    public void awaitTerminatedShouldNotThrowWhenServerFails() throws Exception {
        // Latch to detect when the exception has fired inside connectionOpened()
        CountDownLatch failedLatch = new CountDownLatch(1);

        // Factory that throws RuntimeException on connectionOpened(), simulating
        // any unchecked exception escaping handleKey() into run()
        StreamConnectionFactory throwingFactory = (inetAddress, port) -> new StreamConnection() {
            @Override
            public void connectionOpened() {
                failedLatch.countDown();
                throw new RuntimeException("simulated unchecked exception");
            }

            @Override public void connectionClosed() {}
            @Override public int receiveBytes(ByteBuffer buff) { return 0; }
            @Override public void setWriteTarget(MessageWriteTarget writeTarget) {}
            @Override public int getMaxMessageSize() { return 1000; }
        };

        NioServer server = new NioServer(throwingFactory,
                new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
        server.startAsync();
        server.awaitRunning();
        int port = getPort(server);

        // Connect a client to trigger the RuntimeException in connectionOpened()
        try (Socket client = new Socket()) {
            client.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port));
        }

        // Wait for the exception to fire
        assertTrue("connectionOpened() was not called", failedLatch.await(2, TimeUnit.SECONDS));

        // Wait for Guava to transition to FAILED state
        long deadline = System.currentTimeMillis() + 2000;
        while (server.state() != Service.State.FAILED && System.currentTimeMillis() < deadline) {
            Thread.sleep(10);
        }
        assertEquals("server should be in FAILED state", Service.State.FAILED, server.state());

        // This is the core of the bug: awaitTerminated() throws IllegalStateException
        // on a FAILED service. In stopPeerServers(), this exception propagates through
        // the loop, skipping cleanup of remaining servers.
        //
        // A correct fix should make this NOT throw.
        server.stopAsync();
        server.awaitTerminated();  // currently throws IllegalStateException
    }
}
