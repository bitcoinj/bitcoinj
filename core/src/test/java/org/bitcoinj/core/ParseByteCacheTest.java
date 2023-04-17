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

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.wallet.Wallet;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

import static org.bitcoinj.base.Coin.COIN;
import static org.bitcoinj.base.Coin.valueOf;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeBlock;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeTx;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ParseByteCacheTest {
    private static final int BLOCK_HEIGHT_GENESIS = 0;

    private final byte[] txMessage = ByteUtils.parseHex(
            "f9beb4d974780000000000000000000002010000e293cdbe01000000016dbddb085b1d8af75184f0bc01fad58d1266e9b63b50881990e4b40d6aee3629000000008b483045022100f3581e1972ae8ac7c7367a7a253bc1135223adb9a468bb3a59233f45bc578380022059af01ca17d00e41837a1d58e97aa31bae584edec28d35bd96923690913bae9a0141049c02bfc97ef236ce6d8fe5d94013c721e915982acd2b12b65d9b7d59e20a842005f8fc4e02532e873d37b96f09d6d4511ada8f14042f46614a4c70c0f14beff5ffffffff02404b4c00000000001976a9141aa0cd1cbea6e7458a7abad512a9d9ea1afb225e88ac80fae9c7000000001976a9140eab5bea436a0484cfab12485efda0b78b4ecc5288ac00000000");
    private final byte[] txMessagePart = ByteUtils.parseHex(
            "085b1d8af75184f0bc01fad58d1266e9b63b50881990e4b40d6aee3629000000008b483045022100f3581e1972ae8ac7c7367a7a253bc1135223adb9a468bb3a");

    private BlockStore blockStore;
    
    private byte[] b1Bytes;
    private byte[] b1BytesWithHeader;
    
    private byte[] tx1Bytes;
    private byte[] tx1BytesWithHeader;
    
    private byte[] tx2Bytes;
    private byte[] tx2BytesWithHeader;

    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final NetworkParameters MAINNET = MainNetParams.get();

    private void resetBlockStore() {
        blockStore = new MemoryBlockStore(TESTNET.getGenesisBlock());
    }
    
    @Before
    public void setUp() throws Exception {
        TimeUtils.setMockClock(); // Use mock clock
        Context.propagate(new Context(100, Transaction.DEFAULT_TX_FEE, false, true));
        Wallet wallet = Wallet.createDeterministic(BitcoinNetwork.TESTNET, ScriptType.P2PKH);
        wallet.freshReceiveKey();

        resetBlockStore();
        
        Transaction tx1 = createFakeTx(TESTNET.network(),
                valueOf(2, 0),
                wallet.currentReceiveKey().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET));
        
        // add a second input so can test granularity of byte cache.
        Transaction prevTx = new Transaction();
        TransactionOutput prevOut = new TransactionOutput(prevTx, COIN, wallet.currentReceiveKey().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET));
        prevTx.addOutput(prevOut);
        // Connect it.
        tx1.addInput(prevOut);
        
        Transaction tx2 = createFakeTx(TESTNET.network(), COIN,
                new ECKey().toAddress(ScriptType.P2PKH, BitcoinNetwork.TESTNET));

        Block b1 = createFakeBlock(blockStore, BLOCK_HEIGHT_GENESIS, tx1, tx2).block;

        MessageSerializer serializer = TESTNET.getDefaultSerializer();
        
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        serializer.serialize(tx1, bos);
        tx1BytesWithHeader = bos.toByteArray();
        tx1Bytes = tx1.serialize();
        
        bos.reset();
        serializer.serialize(tx2, bos);
        tx2BytesWithHeader = bos.toByteArray();
        tx2Bytes = tx2.serialize();
        
        bos.reset();
        serializer.serialize(b1, bos);
        b1BytesWithHeader = bos.toByteArray();
        b1Bytes = b1.serialize();
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
    public void testTransactions() throws Exception {
        testTransaction(MAINNET, txMessage, false);
        testTransaction(TESTNET, tx1BytesWithHeader, false);
        testTransaction(TESTNET, tx2BytesWithHeader, false);
    }

    @Test
    public void testBlockAll() throws Exception {
        testBlock(b1BytesWithHeader, false);
    }

    public void testBlock(byte[] blockBytes, boolean isChild) throws Exception {
        // reference serializer to produce comparison serialization output after changes to
        // message structure.
        MessageSerializer serializerRef = TESTNET.getSerializer();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        
        BitcoinSerializer serializer = TESTNET.getSerializer();
        Block b1;
        Block bRef;
        b1 = (Block) serializer.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) serializerRef.deserialize(ByteBuffer.wrap(blockBytes));
        
        // verify our reference BitcoinSerializer produces matching byte array.
        bos.reset();
        serializerRef.serialize(bRef, bos);
        assertArrayEquals(bos.toByteArray(), blockBytes);
        
        // check retain status survive both before and after a serialization
        // "retained mode" was removed from Message, so maybe this test doesn't make much sense any more
        serDeser(serializer, b1, blockBytes, null, null);

        // compare to ref block
        bos.reset();
        serializerRef.serialize(bRef, bos);
        serDeser(serializer, b1, bos.toByteArray(), null, null);
        
        // retrieve a value from a child
        b1.getTransactions();
        if (b1.getTransactions().size() > 0) {
            Transaction tx1 = b1.getTransactions().get(0);
            
            // does it still match ref block?
            serDeser(serializer, b1, bos.toByteArray(), null, null);
        }
        
        // refresh block
        b1 = (Block) serializer.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) serializerRef.deserialize(ByteBuffer.wrap(blockBytes));
        
        // retrieve a value from header
        b1.getDifficultyTarget();
        
        // does it still match ref block?
        serDeser(serializer, b1, bos.toByteArray(), null, null);
        
        // refresh block
        b1 = (Block) serializer.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) serializerRef.deserialize(ByteBuffer.wrap(blockBytes));
        
        // retrieve a value from a child and header
        b1.getDifficultyTarget();

        b1.getTransactions();
        if (b1.getTransactions().size() > 0) {
            Transaction tx1 = b1.getTransactions().get(0);
        }
        // does it still match ref block?
        serDeser(serializer, b1, bos.toByteArray(), null, null);
        
        // refresh block
        b1 = (Block) serializer.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) serializerRef.deserialize(ByteBuffer.wrap(blockBytes));

        // change a value in header
        b1.setNonce(23);
        bRef.setNonce(23);
        // does it still match ref block?
        bos.reset();
        serializerRef.serialize(bRef, bos);
        serDeser(serializer, b1, bos.toByteArray(), null, null);
        
        // refresh block
        b1 = (Block) serializer.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) serializerRef.deserialize(ByteBuffer.wrap(blockBytes));
        
        // retrieve a value from a child of a child
        b1.getTransactions();
        if (b1.getTransactions().size() > 0) {
            Transaction tx1 = b1.getTransactions().get(0);
            
            TransactionInput tin = tx1.getInput(0);

            // does it still match ref tx?
            bos.reset();
            serializerRef.serialize(bRef, bos);
            serDeser(serializer, b1, bos.toByteArray(), null, null);
        }
        
        // refresh block
        b1 = (Block) serializer.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) serializerRef.deserialize(ByteBuffer.wrap(blockBytes));
        
        // add an input
        b1.getTransactions();
        if (b1.getTransactions().size() > 0) {
            Transaction tx1 = b1.getTransactions().get(0);
            
            if (tx1.getInputs().size() > 0) {
                tx1.addInput(tx1.getInput(0));
                // replicate on reference tx
                bRef.getTransactions().get(0).addInput(bRef.getTransactions().get(0).getInput(0));
                
                bos.reset();
                serializerRef.serialize(bRef, bos);
                byte[] source = bos.toByteArray();
                // confirm we still match the reference tx.
                serDeser(serializer, b1, source, null, null);
            }
            
            // does it still match ref tx?
            bos.reset();
            serializerRef.serialize(bRef, bos);
            serDeser(serializer, b1, bos.toByteArray(), null, null);
        }
        
        // refresh block
        b1 = (Block) serializer.deserialize(ByteBuffer.wrap(blockBytes));
        Block b2 = (Block) serializer.deserialize(ByteBuffer.wrap(blockBytes));
        bRef = (Block) serializerRef.deserialize(ByteBuffer.wrap(blockBytes));
        Block bRef2 = (Block) serializerRef.deserialize(ByteBuffer.wrap(blockBytes));
        
        // reparent an input
        b1.getTransactions();
        if (b1.getTransactions().size() > 0) {
            Transaction tx1 = b1.getTransactions().get(0);
            Transaction tx2 = b2.getTransactions().get(0);
            
            if (tx1.getInputs().size() > 0) {
                TransactionInput fromTx1 = tx1.getInput(0);
                tx2.addInput(fromTx1);
                
                // replicate on reference tx
                TransactionInput fromTxRef = bRef.getTransactions().get(0).getInput(0);
                bRef2.getTransactions().get(0).addInput(fromTxRef);
                
                bos.reset();
                serializerRef.serialize(bRef2, bos);
                byte[] source = bos.toByteArray();
                // confirm altered block matches altered ref block.
                serDeser(serializer, b2, source, null, null);
            }
            
            // does unaltered block still match ref block?
            bos.reset();
            serializerRef.serialize(bRef, bos);
            serDeser(serializer, b1, bos.toByteArray(), null, null);

            // how about if we refresh it?
            bRef = (Block) serializerRef.deserialize(ByteBuffer.wrap(blockBytes));
            bos.reset();
            serializerRef.serialize(bRef, bos);
            serDeser(serializer, b1, bos.toByteArray(), null, null);
        }
    }
    
    public void testTransaction(NetworkParameters params, byte[] txBytes, boolean isChild) throws Exception {

        // reference serializer to produce comparison serialization output after changes to
        // message structure.
        MessageSerializer serializerRef = params.getSerializer();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        BitcoinSerializer serializer = params.getSerializer();
        Transaction t1;
        Transaction tRef;
        t1 = (Transaction) serializer.deserialize(ByteBuffer.wrap(txBytes));
        tRef = (Transaction) serializerRef.deserialize(ByteBuffer.wrap(txBytes));

        // verify our reference BitcoinSerializer produces matching byte array.
        bos.reset();
        serializerRef.serialize(tRef, bos);
        assertArrayEquals(bos.toByteArray(), txBytes);

        // check and retain status survive both before and after a serialization
        // "retained mode" was removed from Message, so maybe this test doesn't make much sense any more
        serDeser(serializer, t1, txBytes, null, null);

        // compare to ref tx
        bos.reset();
        serializerRef.serialize(tRef, bos);
        serDeser(serializer, t1, bos.toByteArray(), null, null);
        
        // retrieve a value from a child
        t1.getInputs();
        if (t1.getInputs().size() > 0) {
            TransactionInput tin = t1.getInput(0);

            // does it still match ref tx?
            serDeser(serializer, t1, bos.toByteArray(), null, null);
        }
        
        // refresh tx
        t1 = (Transaction) serializer.deserialize(ByteBuffer.wrap(txBytes));
        tRef = (Transaction) serializerRef.deserialize(ByteBuffer.wrap(txBytes));
        
        // add an input
        if (t1.getInputs().size() > 0) {

            t1.addInput(t1.getInput(0));

            // replicate on reference tx
            tRef.addInput(tRef.getInput(0));

            bos.reset();
            serializerRef.serialize(tRef, bos);
            byte[] source = bos.toByteArray();
            //confirm we still match the reference tx.
            serDeser(serializer, t1, source, null, null);
        }
    }
    
    private void serDeser(MessageSerializer serializer, Message message, byte[] sourceBytes, byte[] containedBytes, byte[] containingBytes) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        serializer.serialize(message, bos);
        byte[] b1 = bos.toByteArray();
        
        Message m2 = serializer.deserialize(ByteBuffer.wrap(b1));

        assertEquals(message, m2);

        bos.reset();
        serializer.serialize(m2, bos);
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

    // Determine if sub is contained in sup.
    public static boolean arrayContains(byte[] sup, byte[] sub) {
        ByteBuffer subBuf = ByteBuffer.wrap(sub);
        int subLength = sub.length;
        int lengthDiff = sup.length - subLength;
        if (lengthDiff < 0)
            return false;
        for (int i = 0; i <= lengthDiff; i++)
            if (ByteBuffer.wrap(sup, i, subLength).equals(subBuf))
                return true;
        return false;
    }

    @Test
    public void testArrayContains() {
        byte[] oneToNine = ByteUtils.parseHex("010203040506070809");
        assertTrue(arrayContains(oneToNine, oneToNine));
        assertTrue(arrayContains(oneToNine, ByteUtils.parseHex("010203")));
        assertTrue(arrayContains(oneToNine, ByteUtils.parseHex("040506")));
        assertTrue(arrayContains(oneToNine, ByteUtils.parseHex("070809")));
        assertTrue(arrayContains(oneToNine, new byte[0]));

        assertFalse(arrayContains(oneToNine, ByteUtils.parseHex("123456")));
        assertFalse(arrayContains(oneToNine, ByteUtils.parseHex("080910")));
        assertFalse(arrayContains(oneToNine, ByteUtils.parseHex("01020304050607080910")));
    }
}
