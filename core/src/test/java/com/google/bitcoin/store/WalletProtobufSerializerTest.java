/**
 * Copyright 2012 Google Inc.
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

package com.google.bitcoin.store;


import com.google.bitcoin.core.*;
import com.google.bitcoin.core.TransactionConfidence.ConfidenceType;
import com.google.bitcoin.params.MainNetParams;
import com.google.bitcoin.params.UnitTestParams;
import com.google.bitcoin.script.ScriptBuilder;
import com.google.bitcoin.utils.BriefLogFormatter;
import com.google.bitcoin.utils.TestUtils;
import com.google.bitcoin.utils.Threading;
import com.google.protobuf.ByteString;
import org.bitcoinj.wallet.Protos;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

import static com.google.bitcoin.utils.TestUtils.createFakeTx;
import static org.junit.Assert.*;

public class WalletProtobufSerializerTest {
    static final NetworkParameters params = UnitTestParams.get();
    private ECKey myKey;
    private ECKey myWatchedKey;
    private Address myAddress;
    private Wallet myWallet;

    public static String WALLET_DESCRIPTION  = "The quick brown fox lives in \u4f26\u6566"; // Beijing in Chinese
    private long mScriptCreationTime;

    @Before
    public void setUp() throws Exception {
        BriefLogFormatter.initVerbose();
        myWatchedKey = new ECKey();
        myKey = new ECKey();
        myKey.setCreationTimeSeconds(123456789L);
        myAddress = myKey.toAddress(params);
        myWallet = new Wallet(params);
        myWallet.addKey(myKey);
        mScriptCreationTime = new Date().getTime() / 1000 - 1234;
        myWallet.addWatchedAddress(myWatchedKey.toAddress(params), mScriptCreationTime);
        myWallet.setDescription(WALLET_DESCRIPTION);
    }

    @Test
    public void empty() throws Exception {
        // Check the base case of a wallet with one key and no transactions.
        Wallet wallet1 = roundTrip(myWallet);
        assertEquals(0, wallet1.getTransactions(true).size());
        assertEquals(BigInteger.ZERO, wallet1.getBalance());
        assertArrayEquals(myKey.getPubKey(),
                wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getPubKey());
        assertArrayEquals(myKey.getPrivKeyBytes(),
                wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getPrivKeyBytes());
        assertEquals(myKey.getCreationTimeSeconds(),
                wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getCreationTimeSeconds());
        assertEquals(mScriptCreationTime,
                wallet1.getWatchedScripts().get(0).getCreationTimeSeconds());
        assertEquals(1, wallet1.getWatchedScripts().size());
        assertEquals(ScriptBuilder.createOutputScript(myWatchedKey.toAddress(params)),
                wallet1.getWatchedScripts().get(0));
        assertEquals(WALLET_DESCRIPTION, wallet1.getDescription());
    }

    @Test
    public void oneTx() throws Exception {
        // Check basic tx serialization.
        BigInteger v1 = Utils.toNanoCoins(1, 0);
        Transaction t1 = createFakeTx(params, v1, myAddress);
        t1.getConfidence().markBroadcastBy(new PeerAddress(InetAddress.getByName("1.2.3.4")));
        t1.getConfidence().markBroadcastBy(new PeerAddress(InetAddress.getByName("5.6.7.8")));
        t1.getConfidence().setSource(TransactionConfidence.Source.NETWORK);
        myWallet.receivePending(t1, null);
        Wallet wallet1 = roundTrip(myWallet);
        assertEquals(1, wallet1.getTransactions(true).size());
        assertEquals(v1, wallet1.getBalance(Wallet.BalanceType.ESTIMATED));
        Transaction t1copy = wallet1.getTransaction(t1.getHash());
        assertArrayEquals(t1.bitcoinSerialize(), t1copy.bitcoinSerialize());
        assertEquals(2, t1copy.getConfidence().numBroadcastPeers());
        assertEquals(TransactionConfidence.Source.NETWORK, t1copy.getConfidence().getSource());
        
        Protos.Wallet walletProto = new WalletProtobufSerializer().walletToProto(myWallet);
        assertEquals(Protos.Key.Type.ORIGINAL, walletProto.getKey(0).getType());
        assertEquals(0, walletProto.getExtensionCount());
        assertEquals(1, walletProto.getTransactionCount());
        assertEquals(1, walletProto.getKeyCount());
        
        Protos.Transaction t1p = walletProto.getTransaction(0);
        assertEquals(0, t1p.getBlockHashCount());
        assertArrayEquals(t1.getHash().getBytes(), t1p.getHash().toByteArray());
        assertEquals(Protos.Transaction.Pool.PENDING, t1p.getPool());
        assertFalse(t1p.hasLockTime());
        assertFalse(t1p.getTransactionInput(0).hasSequence());
        assertArrayEquals(t1.getInputs().get(0).getOutpoint().getHash().getBytes(),
                t1p.getTransactionInput(0).getTransactionOutPointHash().toByteArray());
        assertEquals(0, t1p.getTransactionInput(0).getTransactionOutPointIndex());
        assertEquals(t1p.getTransactionOutput(0).getValue(), v1.longValue());
    }

    @Test
    public void doubleSpend() throws Exception {
        // Check that we can serialize double spends correctly, as this is a slightly tricky case.
        TestUtils.DoubleSpends doubleSpends = TestUtils.createFakeDoubleSpendTxns(params, myAddress);
        // t1 spends to our wallet.
        myWallet.receivePending(doubleSpends.t1, null);
        // t2 rolls back t1 and spends somewhere else.
        myWallet.receiveFromBlock(doubleSpends.t2, null, BlockChain.NewBlockType.BEST_CHAIN, 0);
        Wallet wallet1 = roundTrip(myWallet);
        assertEquals(1, wallet1.getTransactions(true).size());
        Transaction t1 = wallet1.getTransaction(doubleSpends.t1.getHash());
        assertEquals(ConfidenceType.DEAD, t1.getConfidence().getConfidenceType());
        assertEquals(BigInteger.ZERO, wallet1.getBalance());

        // TODO: Wallet should store overriding transactions even if they are not wallet-relevant.
        // assertEquals(doubleSpends.t2, t1.getConfidence().getOverridingTransaction());
    }
    
    @Test
    public void testKeys() throws Exception {
        for (int i = 0 ; i < 20 ; i++) {
            myKey = new ECKey();
            myAddress = myKey.toAddress(params);
            myWallet = new Wallet(params);
            myWallet.addKey(myKey);
            Wallet wallet1 = roundTrip(myWallet);
            assertArrayEquals(myKey.getPubKey(), wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getPubKey());
            assertArrayEquals(myKey.getPrivKeyBytes(), wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getPrivKeyBytes());
        }
    }

    @Test
    public void testLastBlockSeenHash() throws Exception {
        // Test the lastBlockSeenHash field works.

        // LastBlockSeenHash should be empty if never set.
        Wallet wallet = new Wallet(params);
        Protos.Wallet walletProto = new WalletProtobufSerializer().walletToProto(wallet);
        ByteString lastSeenBlockHash = walletProto.getLastSeenBlockHash();
        assertTrue(lastSeenBlockHash.isEmpty());

        // Create a block.
        Block block = new Block(params, BlockTest.blockBytes);
        Sha256Hash blockHash = block.getHash();
        wallet.setLastBlockSeenHash(blockHash);
        wallet.setLastBlockSeenHeight(1);

        // Roundtrip the wallet and check it has stored the blockHash.
        Wallet wallet1 = roundTrip(wallet);
        assertEquals(blockHash, wallet1.getLastBlockSeenHash());
        assertEquals(1, wallet1.getLastBlockSeenHeight());

        // Test the Satoshi genesis block (hash of all zeroes) is roundtripped ok.
        Block genesisBlock = MainNetParams.get().getGenesisBlock();
        wallet.setLastBlockSeenHash(genesisBlock.getHash());
        Wallet wallet2 = roundTrip(wallet);
        assertEquals(genesisBlock.getHash(), wallet2.getLastBlockSeenHash());
    }

    @Test
    public void testAppearedAtChainHeightDepthAndWorkDone() throws Exception {
        // Test the TransactionConfidence appearedAtChainHeight, depth and workDone field are stored.

        BlockChain chain = new BlockChain(params, myWallet, new MemoryBlockStore(params));

        final ArrayList<Transaction> txns = new ArrayList<Transaction>(2);
        myWallet.addEventListener(new AbstractWalletEventListener() {
            @Override
            public void onCoinsReceived(Wallet wallet, Transaction tx, BigInteger prevBalance, BigInteger newBalance) {
                txns.add(tx);
            }
        });

        // Start by building two blocks on top of the genesis block.
        Block b1 = params.getGenesisBlock().createNextBlock(myAddress);
        BigInteger work1 = b1.getWork();
        assertTrue(work1.compareTo(BigInteger.ZERO) > 0);

        Block b2 = b1.createNextBlock(myAddress);
        BigInteger work2 = b2.getWork();
        assertTrue(work2.compareTo(BigInteger.ZERO) > 0);

        assertTrue(chain.add(b1));
        assertTrue(chain.add(b2));

        // We now have the following chain:
        //     genesis -> b1 -> b2

        // Check the transaction confidence levels are correct before wallet roundtrip.
        Threading.waitForUserCode();
        assertEquals(2, txns.size());

        TransactionConfidence confidence0 = txns.get(0).getConfidence();
        TransactionConfidence confidence1 = txns.get(1).getConfidence();

        assertEquals(1, confidence0.getAppearedAtChainHeight());
        assertEquals(2, confidence1.getAppearedAtChainHeight());

        assertEquals(2, confidence0.getDepthInBlocks());
        assertEquals(1, confidence1.getDepthInBlocks());

        assertEquals(work1.add(work2), confidence0.getWorkDone());
        assertEquals(work2, confidence1.getWorkDone());

        // Roundtrip the wallet and check it has stored the depth and workDone.
        Wallet rebornWallet = roundTrip(myWallet);

        Set<Transaction> rebornTxns = rebornWallet.getTransactions(false);
        assertEquals(2, rebornTxns.size());

        // The transactions are not guaranteed to be in the same order so sort them to be in chain height order if required.
        Iterator<Transaction> it = rebornTxns.iterator();
        Transaction txA = it.next();
        Transaction txB = it.next();

        Transaction rebornTx0, rebornTx1;
         if (txA.getConfidence().getAppearedAtChainHeight() == 1) {
            rebornTx0 = txA;
            rebornTx1 = txB;
        } else {
            rebornTx0 = txB;
            rebornTx1 = txA;
        }

        TransactionConfidence rebornConfidence0 = rebornTx0.getConfidence();
        TransactionConfidence rebornConfidence1 = rebornTx1.getConfidence();

        assertEquals(1, rebornConfidence0.getAppearedAtChainHeight());
        assertEquals(2, rebornConfidence1.getAppearedAtChainHeight());

        assertEquals(2, rebornConfidence0.getDepthInBlocks());
        assertEquals(1, rebornConfidence1.getDepthInBlocks());

        assertEquals(work1.add(work2), rebornConfidence0.getWorkDone());
        assertEquals(work2, rebornConfidence1.getWorkDone());
    }

    private static Wallet roundTrip(Wallet wallet) throws Exception {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        //System.out.println(WalletProtobufSerializer.walletToText(wallet));
        new WalletProtobufSerializer().writeWallet(wallet, output);
        ByteArrayInputStream test = new ByteArrayInputStream(output.toByteArray());
        assertTrue(WalletProtobufSerializer.isWallet(test));
        ByteArrayInputStream input = new ByteArrayInputStream(output.toByteArray());
        return new WalletProtobufSerializer().readWallet(input);
    }

    @Test
    public void testRoundTripNormalWallet() throws Exception {
        Wallet wallet1 = roundTrip(myWallet);     
        assertEquals(0, wallet1.getTransactions(true).size());
        assertEquals(BigInteger.ZERO, wallet1.getBalance());
        assertArrayEquals(myKey.getPubKey(),
                wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getPubKey());
        assertArrayEquals(myKey.getPrivKeyBytes(),
                wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getPrivKeyBytes());
        assertEquals(myKey.getCreationTimeSeconds(),
                wallet1.findKeyFromPubHash(myKey.getPubKeyHash()).getCreationTimeSeconds());
    }

    @Test
    public void coinbaseTxns() throws Exception {
        // Covers issue 420 where the outpoint index of a coinbase tx input was being mis-serialized.
        Block b = params.getGenesisBlock().createNextBlockWithCoinbase(myKey.getPubKey(), Utils.toNanoCoins(50, 0));
        Transaction coinbase = b.getTransactions().get(0);
        assertTrue(coinbase.isCoinBase());
        BlockChain chain = new BlockChain(params, myWallet, new MemoryBlockStore(params));
        assertTrue(chain.add(b));
        // Wallet now has a coinbase tx in it.
        assertEquals(1, myWallet.getTransactions(true).size());
        assertTrue(myWallet.getTransaction(coinbase.getHash()).isCoinBase());
        Wallet wallet2 = roundTrip(myWallet);
        assertEquals(1, wallet2.getTransactions(true).size());
        assertTrue(wallet2.getTransaction(coinbase.getHash()).isCoinBase());
    }

    @Test
    public void testExtensions() throws Exception {
        myWallet.addExtension(new SomeFooExtension("com.whatever.required", true));
        Protos.Wallet proto = new WalletProtobufSerializer().walletToProto(myWallet);
        Wallet wallet2 = new Wallet(params);
        // Initial extension is mandatory: try to read it back into a wallet that doesn't know about it.
        try {
            new WalletProtobufSerializer().readWallet(proto, wallet2);
            fail();
        } catch (UnreadableWalletException e) {
            assertTrue(e.getMessage().contains("mandatory"));
        }
        Wallet wallet3 = new Wallet(params);
        // This time it works.
        wallet3.addExtension(new SomeFooExtension("com.whatever.required", true));
        new WalletProtobufSerializer().readWallet(proto, wallet3);
        assertTrue(wallet3.getExtensions().containsKey("com.whatever.required"));


        // Non-mandatory extensions are ignored if the wallet doesn't know how to read them.
        Wallet wallet4 = new Wallet(params);
        wallet4.addExtension(new SomeFooExtension("com.whatever.optional", false));
        Protos.Wallet proto4 = new WalletProtobufSerializer().walletToProto(wallet4);
        Wallet wallet5 = new Wallet(params);
        new WalletProtobufSerializer().readWallet(proto4, wallet5);
        assertEquals(0, wallet5.getExtensions().size());
    }

    private static class SomeFooExtension implements WalletExtension {
        private final byte[] data = new byte[]{1, 2, 3};

        private final boolean isMandatory;
        private final String id;

        public SomeFooExtension(String id, boolean isMandatory) {
            this.isMandatory = isMandatory;
            this.id = id;
        }

        @Override
        public String getWalletExtensionID() {
            return id;
        }

        @Override
        public boolean isWalletExtensionMandatory() {
            return isMandatory;
        }

        @Override
        public byte[] serializeWalletExtension() {
            return data;
        }

        @Override
        public void deserializeWalletExtension(Wallet wallet, byte[] data) {
            assertArrayEquals(this.data, data);
        }
    }
}
