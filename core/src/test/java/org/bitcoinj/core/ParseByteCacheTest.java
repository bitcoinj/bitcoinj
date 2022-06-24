/*
 * Copyright 2011 Steve Coughlan.
 * Copyright 2014 Andreas Schildbach
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

import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.utils.ByteUtils;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.wallet.Wallet;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

import static org.bitcoinj.base.Coin.COIN;
import static org.bitcoinj.base.Coin.valueOf;
import static org.bitcoinj.base.utils.ByteUtils.HEX;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeBlock;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeTx;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ParseByteCacheTest {
    private static final int BLOCK_HEIGHT_GENESIS = 0;

    private final byte[] txMessage = HEX.withSeparator(" ", 2).decode(
            "f9 be b4 d9 74 78 00 00  00 00 00 00 00 00 00 00" +
            "02 01 00 00 e2 93 cd be  01 00 00 00 01 6d bd db" +
            "08 5b 1d 8a f7 51 84 f0  bc 01 fa d5 8d 12 66 e9" +
            "b6 3b 50 88 19 90 e4 b4  0d 6a ee 36 29 00 00 00" +
            "00 8b 48 30 45 02 21 00  f3 58 1e 19 72 ae 8a c7" +
            "c7 36 7a 7a 25 3b c1 13  52 23 ad b9 a4 68 bb 3a" +
            "59 23 3f 45 bc 57 83 80  02 20 59 af 01 ca 17 d0" +
            "0e 41 83 7a 1d 58 e9 7a  a3 1b ae 58 4e de c2 8d" +
            "35 bd 96 92 36 90 91 3b  ae 9a 01 41 04 9c 02 bf" +
            "c9 7e f2 36 ce 6d 8f e5  d9 40 13 c7 21 e9 15 98" +
            "2a cd 2b 12 b6 5d 9b 7d  59 e2 0a 84 20 05 f8 fc" +
            "4e 02 53 2e 87 3d 37 b9  6f 09 d6 d4 51 1a da 8f" +
            "14 04 2f 46 61 4a 4c 70  c0 f1 4b ef f5 ff ff ff" +
            "ff 02 40 4b 4c 00 00 00  00 00 19 76 a9 14 1a a0" +
            "cd 1c be a6 e7 45 8a 7a  ba d5 12 a9 d9 ea 1a fb" +
            "22 5e 88 ac 80 fa e9 c7  00 00 00 00 19 76 a9 14" +
            "0e ab 5b ea 43 6a 04 84  cf ab 12 48 5e fd a0 b7" +
            "8b 4e cc 52 88 ac 00 00  00 00");
    
    private final byte[] txMessagePart = HEX.withSeparator(" ", 2).decode(
            "08 5b 1d 8a f7 51 84 f0  bc 01 fa d5 8d 12 66 e9" +
            "b6 3b 50 88 19 90 e4 b4  0d 6a ee 36 29 00 00 00" +
            "00 8b 48 30 45 02 21 00  f3 58 1e 19 72 ae 8a c7" +
            "c7 36 7a 7a 25 3b c1 13  52 23 ad b9 a4 68 bb 3a");

    private BlockStore blockStore;
    
    private byte[] b1Bytes;
    private byte[] b1BytesWithHeader;
    
    private byte[] tx1Bytes;
    private byte[] tx1BytesWithHeader;
    
    private byte[] tx2Bytes;
    private byte[] tx2BytesWithHeader;

    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    private void resetBlockStore() {
        blockStore = new MemoryBlockStore(UNITTEST);
    }
    
    @Before
    public void setUp() throws Exception {
        Utils.setMockClock(); // Use mock clock
        Wallet wallet = Wallet.createDeterministic(UNITTEST, ScriptType.P2PKH);
        wallet.freshReceiveKey();

        resetBlockStore();
        
        Transaction tx1 = createFakeTx(UNITTEST,
                valueOf(2, 0),
                LegacyAddress.fromKey(UNITTEST, wallet.currentReceiveKey()));
        
        // add a second input so can test granularity of byte cache.
        Transaction prevTx = new Transaction(UNITTEST);
        TransactionOutput prevOut = new TransactionOutput(UNITTEST, prevTx, COIN, LegacyAddress.fromKey(UNITTEST, wallet.currentReceiveKey()));
        prevTx.addOutput(prevOut);
        // Connect it.
        tx1.addInput(prevOut);
        
        Transaction tx2 = createFakeTx(UNITTEST, COIN,
                LegacyAddress.fromKey(UNITTEST, new ECKey()));

        Block b1 = createFakeBlock(blockStore, BLOCK_HEIGHT_GENESIS, tx1, tx2).block;

        MessageSerializer bs = UNITTEST.getDefaultSerializer();
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bs.serialize(tx1, bos);
        tx1BytesWithHeader = bos.toByteArray();
        tx1Bytes = tx1.bitcoinSerialize();
        
        bos.reset();
        bs.serialize(tx2, bos);
        tx2BytesWithHeader = bos.toByteArray();
        tx2Bytes = tx2.bitcoinSerialize();
        
        bos.reset();
        bs.serialize(b1, bos);
        b1BytesWithHeader = bos.toByteArray();
        b1Bytes = b1.bitcoinSerialize();
    }
    
    @Test
    public void validateSetup() {
        byte[] b1 = {1, 1, 1, 2, 3, 4, 5, 6, 7};
        byte[] b2 = {1, 2, 3};
        assertTrue(arrayContains(b1, b2));
        assertTrue(arrayContains(txMessage, txMessagePart));
        assertTrue(arrayContains(tx1BytesWithHeader, tx1Bytes));
        assertTrue(arrayContains(tx2BytesWithHeader, tx2Bytes));
        assertTrue(arrayContains(b1BytesWithHeader, b1Bytes));
        assertTrue(arrayContains(b1BytesWithHeader, tx1Bytes));
        assertTrue(arrayContains(b1BytesWithHeader, tx2Bytes));
        assertFalse(arrayContains(tx1BytesWithHeader, b1Bytes));
    }
    
    @Test
    public void testTransactionsRetain() throws Exception {
        testTransaction(MAINNET, txMessage, false, true);
        testTransaction(UNITTEST, tx1BytesWithHeader, false, true);
        testTransaction(UNITTEST, tx2BytesWithHeader, false, true);
    }
    
    @Test
    public void testTransactionsNoRetain() throws Exception {
        testTransaction(MAINNET, txMessage, false, false);
        testTransaction(UNITTEST, tx1BytesWithHeader, false, false);
        testTransaction(UNITTEST, tx2BytesWithHeader, false, false);
    }

    @Test
    public void testBlockAll() throws Exception {
        testBlock(b1BytesWithHeader, false, false);
        testBlock(b1BytesWithHeader, false, true);
    }

    public void testBlock(byte[] blockBytes, boolean isChild, boolean retain) throws Exception {
        // reference serializer to produce comparison serialization output after changes to
        // message structure.
        MessageSerializer bsRef = UNITTEST.getSerializer(false);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        
        BitcoinSerializer bs = UNITTEST.getSerializer(retain);
        Block b1;
        Block bRef;
        b1 = (Block) bs.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) bsRef.deserialize(ByteBuffer.wrap(blockBytes));
        
        // verify our reference BitcoinSerializer produces matching byte array.
        bos.reset();
        bsRef.serialize(bRef, bos);
        assertArrayEquals(bos.toByteArray(), blockBytes);
        
        // check retain status survive both before and after a serialization
        assertEquals(retain, b1.isHeaderBytesValid());
        assertEquals(retain, b1.isTransactionBytesValid());
        
        serDeser(bs, b1, blockBytes, null, null);
        
        assertEquals(retain, b1.isHeaderBytesValid());
        assertEquals(retain, b1.isTransactionBytesValid());
        
        // compare to ref block
        bos.reset();
        bsRef.serialize(bRef, bos);
        serDeser(bs, b1, bos.toByteArray(), null, null);
        
        // retrieve a value from a child
        b1.getTransactions();
        if (b1.getTransactions().size() > 0) {
            Transaction tx1 = b1.getTransactions().get(0);
            
            // this will always be true for all children of a block once they are retrieved.
            // the tx child inputs/outputs may not be parsed however.
            
            assertEquals(retain, tx1.isCached());
            
            // does it still match ref block?
            serDeser(bs, b1, bos.toByteArray(), null, null);
        }
        
        // refresh block
        b1 = (Block) bs.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) bsRef.deserialize(ByteBuffer.wrap(blockBytes));
        
        // retrieve a value from header
        b1.getDifficultyTarget();
        
        // does it still match ref block?
        serDeser(bs, b1, bos.toByteArray(), null, null);
        
        // refresh block
        b1 = (Block) bs.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) bsRef.deserialize(ByteBuffer.wrap(blockBytes));
        
        // retrieve a value from a child and header
        b1.getDifficultyTarget();

        b1.getTransactions();
        if (b1.getTransactions().size() > 0) {
            Transaction tx1 = b1.getTransactions().get(0);
            
            assertEquals(retain, tx1.isCached());
        }
        // does it still match ref block?
        serDeser(bs, b1, bos.toByteArray(), null, null);
        
        // refresh block
        b1 = (Block) bs.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) bsRef.deserialize(ByteBuffer.wrap(blockBytes));

        // change a value in header
        b1.setNonce(23);
        bRef.setNonce(23);
        assertFalse(b1.isHeaderBytesValid());
        assertEquals(retain , b1.isTransactionBytesValid());
        // does it still match ref block?
        bos.reset();
        bsRef.serialize(bRef, bos);
        serDeser(bs, b1, bos.toByteArray(), null, null);
        
        // refresh block
        b1 = (Block) bs.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) bsRef.deserialize(ByteBuffer.wrap(blockBytes));
        
        // retrieve a value from a child of a child
        b1.getTransactions();
        if (b1.getTransactions().size() > 0) {
            Transaction tx1 = b1.getTransactions().get(0);
            
            TransactionInput tin = tx1.getInputs().get(0);
            
            assertEquals(retain, tin.isCached());
            
            // does it still match ref tx?
            bos.reset();
            bsRef.serialize(bRef, bos);
            serDeser(bs, b1, bos.toByteArray(), null, null);
        }
        
        // refresh block
        b1 = (Block) bs.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) bsRef.deserialize(ByteBuffer.wrap(blockBytes));
        
        // add an input
        b1.getTransactions();
        if (b1.getTransactions().size() > 0) {
            Transaction tx1 = b1.getTransactions().get(0);
            
            if (tx1.getInputs().size() > 0) {
                tx1.addInput(tx1.getInputs().get(0));
                // replicate on reference tx
                bRef.getTransactions().get(0).addInput(bRef.getTransactions().get(0).getInputs().get(0));
                
                assertFalse(tx1.isCached());
                assertFalse(b1.isTransactionBytesValid());
                
                // confirm sibling cache status was unaffected
                if (tx1.getInputs().size() > 1) {
                    assertEquals(retain, tx1.getInputs().get(1).isCached());
                }
                
                // this has to be false. Altering a tx invalidates the merkle root.
                // when we have seperate merkle caching then the entire header won't need to be
                // invalidated.
                assertFalse(b1.isHeaderBytesValid());
                
                bos.reset();
                bsRef.serialize(bRef, bos);
                byte[] source = bos.toByteArray();
                // confirm we still match the reference tx.
                serDeser(bs, b1, source, null, null);
            }
            
            // does it still match ref tx?
            bos.reset();
            bsRef.serialize(bRef, bos);
            serDeser(bs, b1, bos.toByteArray(), null, null);
        }
        
        // refresh block
        b1 = (Block) bs.deserialize(ByteBuffer.wrap(blockBytes));
        Block b2 = (Block) bs.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) bsRef.deserialize(ByteBuffer.wrap(blockBytes));
        Block bRef2 = (Block) bsRef.deserialize(ByteBuffer.wrap(blockBytes));
        
        // reparent an input
        b1.getTransactions();
        if (b1.getTransactions().size() > 0) {
            Transaction tx1 = b1.getTransactions().get(0);
            Transaction tx2 = b2.getTransactions().get(0);
            
            if (tx1.getInputs().size() > 0) {
                TransactionInput fromTx1 = tx1.getInputs().get(0);
                tx2.addInput(fromTx1);
                
                // replicate on reference tx
                TransactionInput fromTxRef = bRef.getTransactions().get(0).getInputs().get(0);
                bRef2.getTransactions().get(0).addInput(fromTxRef);
                
                // b1 hasn't changed but it's no longer in the parent
                // chain of fromTx1 so has to have been uncached since it won't be
                // notified of changes throught the parent chain anymore.
                assertFalse(b1.isTransactionBytesValid());
                
                // b2 should have it's cache invalidated because it has changed.
                assertFalse(b2.isTransactionBytesValid());
                
                bos.reset();
                bsRef.serialize(bRef2, bos);
                byte[] source = bos.toByteArray();
                // confirm altered block matches altered ref block.
                serDeser(bs, b2, source, null, null);
            }
            
            // does unaltered block still match ref block?
            bos.reset();
            bsRef.serialize(bRef, bos);
            serDeser(bs, b1, bos.toByteArray(), null, null);

            // how about if we refresh it?
            bRef = (Block) bsRef.deserialize(ByteBuffer.wrap(blockBytes));
            bos.reset();
            bsRef.serialize(bRef, bos);
            serDeser(bs, b1, bos.toByteArray(), null, null);
        }
    }
    
    public void testTransaction(NetworkParameters params, byte[] txBytes, boolean isChild, boolean retain) throws Exception {

        // reference serializer to produce comparison serialization output after changes to
        // message structure.
        MessageSerializer bsRef = params.getSerializer(false);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        BitcoinSerializer bs = params.getSerializer(retain);
        Transaction t1;
        Transaction tRef;
        t1 = (Transaction) bs.deserialize(ByteBuffer.wrap(txBytes));
        tRef = (Transaction) bsRef.deserialize(ByteBuffer.wrap(txBytes));

        // verify our reference BitcoinSerializer produces matching byte array.
        bos.reset();
        bsRef.serialize(tRef, bos);
        assertArrayEquals(bos.toByteArray(), txBytes);

        // check and retain status survive both before and after a serialization
        assertEquals(retain, t1.isCached());

        serDeser(bs, t1, txBytes, null, null);

        assertEquals(retain, t1.isCached());

        // compare to ref tx
        bos.reset();
        bsRef.serialize(tRef, bos);
        serDeser(bs, t1, bos.toByteArray(), null, null);
        
        // retrieve a value from a child
        t1.getInputs();
        if (t1.getInputs().size() > 0) {
            TransactionInput tin = t1.getInputs().get(0);
            assertEquals(retain, tin.isCached());
            
            // does it still match ref tx?
            serDeser(bs, t1, bos.toByteArray(), null, null);
        }
        
        // refresh tx
        t1 = (Transaction) bs.deserialize(ByteBuffer.wrap(txBytes));
        tRef = (Transaction) bsRef.deserialize(ByteBuffer.wrap(txBytes));
        
        // add an input
        if (t1.getInputs().size() > 0) {

            t1.addInput(t1.getInputs().get(0));

            // replicate on reference tx
            tRef.addInput(tRef.getInputs().get(0));

            assertFalse(t1.isCached());

            bos.reset();
            bsRef.serialize(tRef, bos);
            byte[] source = bos.toByteArray();
            //confirm we still match the reference tx.
            serDeser(bs, t1, source, null, null);
        }
    }
    
    private void serDeser(MessageSerializer bs, Message message, byte[] sourceBytes, byte[] containedBytes, byte[] containingBytes) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bs.serialize(message, bos);
        byte[] b1 = bos.toByteArray();
        
        Message m2 = bs.deserialize(ByteBuffer.wrap(b1));

        assertEquals(message, m2);

        bos.reset();
        bs.serialize(m2, bos);
        byte[] b2 = bos.toByteArray();
        assertArrayEquals(b1, b2);

        if (sourceBytes != null) {
            assertTrue(arrayContains(sourceBytes, b1));
            
            assertTrue(arrayContains(sourceBytes, b2));
        }

        if (containedBytes != null) {
            assertTrue(arrayContains(b1, containedBytes));
        }
        if (containingBytes != null) {
            assertTrue(arrayContains(containingBytes, b1));
        }
    }
    
    public static boolean arrayContains(byte[] sup, byte[] sub) {
        if (sup.length < sub.length)
            return false;       
        
        String superstring = ByteUtils.HEX.encode(sup);
        String substring = ByteUtils.HEX.encode(sub);
        
        int ind = superstring.indexOf(substring);
        
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < superstring.indexOf(substring); i++)
            sb.append(" ");
        
        //System.out.println(superstring);
        //System.out.println(sb.append(substring).toString());
        //System.out.println();
        return ind > -1;
    }
}
