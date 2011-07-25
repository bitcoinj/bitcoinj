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

import static org.junit.Assert.assertTrue;

import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.MemoryBlockStore;

import org.junit.Before;
import org.junit.Test;

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
        peerGroup = new PeerGroup(blockStore, params, chain);
    }

    @Test
    public void listener() throws Exception {
        AbstractPeerEventListener listener = new AbstractPeerEventListener() {
        };
        peerGroup.addEventListener(listener);
        assertTrue(peerGroup.removeEventListener(listener));
    }
}
