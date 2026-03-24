/*
 * Copyright 2026 the bitcoinj contributors
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

package org.bitcoinj.test.integration.peer;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Tests for the {@link TestWithNetworkConnections} test fixture itself.
 */
public class TestWithNetworkConnectionsTest {

    // Reproducer for https://github.com/bitcoinj/bitcoinj/issues/1984
    @Test
    public void stopPeerServersContinuesAfterException() {
        final int[] stopCount = {0};

        TestWithNetworkConnections fixture = new TestWithNetworkConnections(
                TestWithNetworkConnections.ClientType.NIO_CLIENT_MANAGER) {
            @Override
            protected void stopPeerServer(int i) {
                stopCount[0]++;
                if (i == 0) {
                    throw new IllegalStateException("simulated: server entered FAILED state");
                }
            }
        };

        // Call stopPeerServers() directly without setUp() to avoid port conflicts.
        // Without the fix, the loop aborts when server 0 throws and only 1 server
        // is visited. With the fix, all PEER_SERVERS are visited.
        fixture.stopPeerServers();

        assertEquals(TestWithNetworkConnections.PEER_SERVERS, stopCount[0]);
    }
}
