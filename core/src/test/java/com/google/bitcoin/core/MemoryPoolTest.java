/*
 * Copyright 2012 Google Inc.
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

import com.google.bitcoin.params.UnitTestParams;
import com.google.bitcoin.testing.FakeTxBuilder;
import com.google.bitcoin.utils.BriefLogFormatter;
import org.junit.Before;
import org.junit.Test;

import java.net.InetAddress;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class MemoryPoolTest {
    private NetworkParameters params = UnitTestParams.get();
    private Transaction tx1, tx2;
    private PeerAddress address1, address2, address3;

    @Before
    public void setup() throws Exception {
        BriefLogFormatter.init();
        tx1 = FakeTxBuilder.createFakeTx(params, Utils.toNanoCoins(1, 0), new ECKey().toAddress(params));
        tx2 = new Transaction(params, tx1.bitcoinSerialize());

        address1 = new PeerAddress(InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }));
        address2 = new PeerAddress(InetAddress.getByAddress(new byte[] { 127, 0, 0, 2 }));
        address3 = new PeerAddress(InetAddress.getByAddress(new byte[] { 127, 0, 0, 3 }));
    }

    @Test
    public void canonicalInstance() throws Exception {
        MemoryPool pool = new MemoryPool();
        // Check that if we repeatedly send it the same transaction but with different objects, we get back the same
        // canonical instance with the confidences update.
        assertEquals(0, pool.numBroadcastPeers(tx1.getHash()));
        assertEquals(tx1, pool.seen(tx1, address1));
        assertEquals(1, tx1.getConfidence().numBroadcastPeers());
        assertEquals(1, pool.numBroadcastPeers(tx1.getHash()));
        assertEquals(tx1, pool.seen(tx2, address2));
        assertEquals(2, tx1.getConfidence().numBroadcastPeers());
        assertEquals(2, pool.numBroadcastPeers(tx1.getHash()));
        assertEquals(tx1, pool.get(tx1.getHash()));
    }
    
    @Test
    public void invAndDownload() throws Exception {
        MemoryPool pool = new MemoryPool();
        // Base case: we see a transaction announced twice and then download it. The count is in the confidence object.
        assertEquals(0, pool.numBroadcastPeers(tx1.getHash()));
        pool.seen(tx1.getHash(), address1);
        assertEquals(1, pool.numBroadcastPeers(tx1.getHash()));
        assertTrue(pool.maybeWasSeen(tx1.getHash()));
        pool.seen(tx1.getHash(), address2);
        assertEquals(2, pool.numBroadcastPeers(tx1.getHash()));
        Transaction t = pool.seen(tx1,  address1);
        assertEquals(2, t.getConfidence().numBroadcastPeers());
        // And now we see another inv.
        pool.seen(tx1.getHash(), address3);
        assertEquals(3, t.getConfidence().numBroadcastPeers());
        assertEquals(3, pool.numBroadcastPeers(tx1.getHash()));
    }
}
