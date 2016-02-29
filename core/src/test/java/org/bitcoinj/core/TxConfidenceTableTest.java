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

package org.bitcoinj.core;

import org.bitcoinj.params.*;
import org.bitcoinj.testing.*;
import org.bitcoinj.utils.*;
import org.junit.*;

import java.net.*;

import static org.bitcoinj.core.Coin.*;
import static org.junit.Assert.*;

public class TxConfidenceTableTest {
    private static final NetworkParameters PARAMS = UnitTestParams.get();
    private Transaction tx1, tx2;
    private PeerAddress address1, address2, address3;
    private TxConfidenceTable table;

    @Before
    public void setup() throws Exception {
        BriefLogFormatter.init();
        Context context = new Context(PARAMS);
        table = context.getConfidenceTable();

        Address to = new ECKey().toAddress(PARAMS);
        Address change = new ECKey().toAddress(PARAMS);

        tx1 = FakeTxBuilder.createFakeTxWithChangeAddress(PARAMS, COIN, to, change);
        tx2 = FakeTxBuilder.createFakeTxWithChangeAddress(PARAMS, COIN, to, change);
        assertEquals(tx1.getHash(), tx2.getHash());

        address1 = new PeerAddress(PARAMS, InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }));
        address2 = new PeerAddress(PARAMS, InetAddress.getByAddress(new byte[] { 127, 0, 0, 2 }));
        address3 = new PeerAddress(PARAMS, InetAddress.getByAddress(new byte[] { 127, 0, 0, 3 }));
    }

    @Test
    public void pinHandlers() throws Exception {
        Transaction tx = PARAMS.getDefaultSerializer().makeTransaction(tx1.bitcoinSerialize());
        Sha256Hash hash = tx.getHash();
        table.seen(hash, address1);
        assertEquals(1, tx.getConfidence().numBroadcastPeers());
        final int[] seen = new int[1];
        tx.getConfidence().addEventListener(Threading.SAME_THREAD, new TransactionConfidence.Listener() {
            @Override
            public void onConfidenceChanged(TransactionConfidence confidence, ChangeReason reason) {
                seen[0] = confidence.numBroadcastPeers();
            }
        });
        tx = null;
        System.gc();
        table.seen(hash, address2);
        assertEquals(2, seen[0]);
    }

    @Test
    public void events() throws Exception {
        final TransactionConfidence.Listener.ChangeReason[] run = new TransactionConfidence.Listener.ChangeReason[1];
        tx1.getConfidence().addEventListener(Threading.SAME_THREAD, new TransactionConfidence.Listener() {
            @Override
            public void onConfidenceChanged(TransactionConfidence confidence, ChangeReason reason) {
                run[0] = reason;
            }
        });
        table.seen(tx1.getHash(), address1);
        assertEquals(TransactionConfidence.Listener.ChangeReason.SEEN_PEERS, run[0]);
        run[0] = null;
        table.seen(tx1.getHash(), address1);
        assertNull(run[0]);
    }

    @Test
    public void invAndDownload() throws Exception {
        // Base case: we see a transaction announced twice and then download it. The count is in the confidence object.
        assertEquals(0, table.numBroadcastPeers(tx1.getHash()));
        table.seen(tx1.getHash(), address1);
        assertEquals(1, table.numBroadcastPeers(tx1.getHash()));
        table.seen(tx1.getHash(), address2);
        assertEquals(2, table.numBroadcastPeers(tx1.getHash()));
        assertEquals(2, tx2.getConfidence().numBroadcastPeers());
        // And now we see another inv.
        table.seen(tx1.getHash(), address3);
        assertEquals(3, tx2.getConfidence().numBroadcastPeers());
        assertEquals(3, table.numBroadcastPeers(tx1.getHash()));
    }
}
