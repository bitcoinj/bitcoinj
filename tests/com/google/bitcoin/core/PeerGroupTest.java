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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.google.bitcoin.discovery.PeerDiscovery;
import com.google.bitcoin.discovery.PeerDiscoveryException;
import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.MemoryBlockStore;

import org.junit.Before;
import org.junit.Test;

import java.net.InetSocketAddress;
import java.util.concurrent.Semaphore;

public class PeerGroupTest {
    static final NetworkParameters params = NetworkParameters.unitTests();

    private Wallet wallet;
    private BlockStore blockStore;
    private PeerGroup peerGroup;

    @Before
    public void setUp() throws Exception {
        wallet = new Wallet(params);
        blockStore = new MemoryBlockStore(params);
        BlockChain chain = new BlockChain(params, wallet, blockStore);
        peerGroup = new PeerGroup(blockStore, params, chain, 1000);
    }

    @Test
    public void listener() throws Exception {
        AbstractPeerEventListener listener = new AbstractPeerEventListener() {
        };
        peerGroup.addEventListener(listener);
        assertTrue(peerGroup.removeEventListener(listener));
    }

    @Test
    public void peerDiscoveryPolling() throws Exception {
        // Check that if peer discovery fails, we keep trying until we have some nodes to talk with.
        final Semaphore sem = new Semaphore(0);
        final boolean[] result = new boolean[1];
        result[0] = false;
        peerGroup.addPeerDiscovery(new PeerDiscovery() {
            public InetSocketAddress[] getPeers() throws PeerDiscoveryException {
                if (result[0] == false) {
                    // Pretend we are not connected to the internet.
                    result[0] = true;
                    throw new PeerDiscoveryException("test failure");
                } else {
                    // Return a bogus address.
                    sem.release();
                    return new InetSocketAddress[]{new InetSocketAddress("localhost", 0)};
                }
            }
        });
        peerGroup.start();
        sem.acquire();
        // Check that we did indeed throw an exception. If we got here it means we threw and then PeerGroup tried
        // again a bit later.
        assertTrue(result[0]);
        peerGroup.stop();
    }
}
