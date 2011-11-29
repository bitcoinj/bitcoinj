/*
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

import com.google.bitcoin.store.MemoryBlockStore;
import com.google.bitcoin.utils.BriefLogFormatter;
import org.easymock.IMocksControl;

import java.io.IOException;

import static org.easymock.EasyMock.*;

/**
 * Utility class that makes it easy to work with mock NetworkConnections.
 */
public class TestWithNetworkConnections {
    protected IMocksControl control;
    protected NetworkParameters unitTestParams;
    protected MemoryBlockStore blockStore;
    protected BlockChain blockChain;
    protected Wallet wallet;
    protected ECKey key;
    protected Address address;

    public void setUp() throws Exception {
        BriefLogFormatter.init();

        control = createStrictControl();
        control.checkOrder(true);

        unitTestParams = NetworkParameters.unitTests();
        blockStore = new MemoryBlockStore(unitTestParams);
        wallet = new Wallet(unitTestParams);
        key = new ECKey();
        address = key.toAddress(unitTestParams);
        wallet.addKey(key);
        blockChain = new BlockChain(unitTestParams, wallet, blockStore);
    }

    protected MockNetworkConnection createMockNetworkConnection() {
        return new MockNetworkConnection();
    }

    protected void runPeer(Peer peer, MockNetworkConnection connection) throws IOException, PeerException {
        connection.disconnect();
        try {
            peer.run();
        } catch (PeerException e) {
            if (!e.getCause().getMessage().equals("done"))
                throw e;
        }
    }

    protected void runPeerAsync(final Peer peer, MockNetworkConnection connection) throws IOException, PeerException {
        new Thread("Test Peer Thread") {
            @Override
            public void run() {
                try {
                    peer.run();
                } catch (PeerException e) {
                    if (!e.getCause().getMessage().equals("done")) throw new RuntimeException(e);
                }
            }
        }.start();
    }
}
