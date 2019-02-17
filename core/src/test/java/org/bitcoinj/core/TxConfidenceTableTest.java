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

import static org.bitcoinj.core.Coin.COIN;
import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.easymock.EasyMock.replay;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class TxConfidenceTableTest {
    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private Transaction tx1, tx2;
    private PeerAddress address1, address2, address3;
    private TxConfidenceTable table;

    @Before
    public void setup() throws Exception {
        BriefLogFormatter.init();
        Context context = new Context(UNITTEST);
        table = context.getConfidenceTable();

        Address to = LegacyAddress.fromKey(UNITTEST, new ECKey());
        Address change = LegacyAddress.fromKey(UNITTEST, new ECKey());

        tx1 = FakeTxBuilder.createFakeTxWithChangeAddress(UNITTEST, COIN, to, change);
        tx2 = FakeTxBuilder.createFakeTxWithChangeAddress(UNITTEST, COIN, to, change);
        assertEquals(tx1.getTxId(), tx2.getTxId());

        address1 = new PeerAddress(UNITTEST, InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }));
        address2 = new PeerAddress(UNITTEST, InetAddress.getByAddress(new byte[] { 127, 0, 0, 2 }));
        address3 = new PeerAddress(UNITTEST, InetAddress.getByAddress(new byte[] { 127, 0, 0, 3 }));
    }

    @Test
    public void pinHandlers() throws Exception {
        Transaction tx = UNITTEST.getDefaultSerializer().makeTransaction(tx1.bitcoinSerialize());
        Sha256Hash hash = tx.getTxId();
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
        table.seen(tx1.getTxId(), address1);
        assertEquals(TransactionConfidence.Listener.ChangeReason.SEEN_PEERS, run[0]);
        run[0] = null;
        table.seen(tx1.getTxId(), address1);
        assertNull(run[0]);
    }

    @Test
    public void testSeen() {
        PeerAddress peer = createMock(PeerAddress.class);

        Sha256Hash brokenHash = createMock(Sha256Hash.class);
        Sha256Hash correctHash = createMock(Sha256Hash.class);

        TransactionConfidence brokenConfidence = createMock(TransactionConfidence.class);
        expect(brokenConfidence.getTransactionHash()).andReturn(brokenHash);
        expect(brokenConfidence.markBroadcastBy(peer)).andThrow(new ArithmeticException("some error"));

        TransactionConfidence correctConfidence = createMock(TransactionConfidence.class);
        expect(correctConfidence.getTransactionHash()).andReturn(correctHash);
        expect(correctConfidence.markBroadcastBy(peer)).andReturn(true);
        correctConfidence.queueListeners(anyObject(TransactionConfidence.Listener.ChangeReason.class));
        expectLastCall();

        TransactionConfidence.Factory factory = createMock(TransactionConfidence.Factory.class);
        expect(factory.createConfidence(brokenHash)).andReturn(brokenConfidence);
        expect(factory.createConfidence(correctHash)).andReturn(correctConfidence);

        replay(factory, brokenConfidence, correctConfidence);

        TxConfidenceTable table = new TxConfidenceTable(1, factory);

        try {
            table.seen(brokenHash, peer);
        } catch (ArithmeticException expected) {
            // do nothing
        }

        assertNotNull(table.seen(correctHash, peer));
    }

    @Test
    public void invAndDownload() throws Exception {
        // Base case: we see a transaction announced twice and then download it. The count is in the confidence object.
        assertEquals(0, table.numBroadcastPeers(tx1.getTxId()));
        table.seen(tx1.getTxId(), address1);
        assertEquals(1, table.numBroadcastPeers(tx1.getTxId()));
        table.seen(tx1.getTxId(), address2);
        assertEquals(2, table.numBroadcastPeers(tx1.getTxId()));
        assertEquals(2, tx2.getConfidence().numBroadcastPeers());
        // And now we see another inv.
        table.seen(tx1.getTxId(), address3);
        assertEquals(3, tx2.getConfidence().numBroadcastPeers());
        assertEquals(3, table.numBroadcastPeers(tx1.getTxId()));
    }
}
