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

package com.google.bitcoin.utils;

import com.google.bitcoin.core.*;
import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.BlockStoreException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;

public class TestUtils {
    public static Transaction createFakeTxWithChangeAddress(NetworkParameters params, BigInteger nanocoins, Address to, Address changeOutput)
            throws IOException, ProtocolException {
        // Create a fake TX of sufficient realism to exercise the unit tests. Two outputs, one to us, one to somewhere
        // else to simulate change.
        Transaction t = new Transaction(params);
        TransactionOutput outputToMe = new TransactionOutput(params, t, nanocoins, to);
        t.addOutput(outputToMe);
        TransactionOutput change = new TransactionOutput(params, t, Utils.toNanoCoins(1, 11), changeOutput);
        t.addOutput(change);
        // Make a previous tx simply to send us sufficient coins. This prev tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, prevTx, nanocoins, to);
        prevTx.addOutput(prevOut);
        // Connect it.
        t.addInput(prevOut);
        // Serialize/deserialize to ensure internal state is stripped, as if it had been read from the wire.
        return roundTripTransaction(params, t);
    }

    public static Transaction createFakeTx(NetworkParameters params, BigInteger nanocoins, Address to) throws IOException, ProtocolException {
        return createFakeTxWithChangeAddress(params, nanocoins, to, new ECKey().toAddress(params));
    }

    public static Transaction createFakeTx(NetworkParameters params, BigInteger nanocoins, ECKey to) throws IOException, ProtocolException {
        // Create a fake TX of sufficient realism to exercise the unit tests. Two outputs, one to us, one to somewhere
        // else to simulate change.
        Transaction t = new Transaction(params);
        TransactionOutput outputToMe = new TransactionOutput(params, t, nanocoins, to);
        t.addOutput(outputToMe);
        TransactionOutput change = new TransactionOutput(params, t, Utils.toNanoCoins(1, 11), new ECKey());
        t.addOutput(change);
        // Make a previous tx simply to send us sufficient coins. This prev tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, prevTx, nanocoins, to);
        prevTx.addOutput(prevOut);
        // Connect it.
        t.addInput(prevOut);
        // Serialize/deserialize to ensure internal state is stripped, as if it had been read from the wire.
        return roundTripTransaction(params, t);
    }

    /**
     * @return Transaction[] Transaction[0] is a feeder transaction, supplying BTC to Transaction[1]
     */
    public static Transaction[] createFakeTx(NetworkParameters params, BigInteger nanocoins,
                                             Address to, Address from) throws IOException, ProtocolException {
        // Create fake TXes of sufficient realism to exercise the unit tests. This transaction send BTC from the
        // from address, to the to address with to one to somewhere else to simulate change.
        Transaction t = new Transaction(params);
        TransactionOutput outputToMe = new TransactionOutput(params, t, nanocoins, to);
        t.addOutput(outputToMe);
        TransactionOutput change = new TransactionOutput(params, t, Utils.toNanoCoins(1, 11), new ECKey().toAddress(params));
        t.addOutput(change);
        // Make a feeder tx that sends to the from address specified. This feeder tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction feederTx = new Transaction(params);
        TransactionOutput feederOut = new TransactionOutput(params, feederTx, nanocoins, from);
        feederTx.addOutput(feederOut);

        // make a previous tx that sends from the feeder to the from address
        Transaction prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, prevTx, nanocoins, to);
        prevTx.addOutput(prevOut);

        // Connect up the txes
        prevTx.addInput(feederOut);
        t.addInput(prevOut);

        // roundtrip the tx so that they are just like they would be from the wire
        return new Transaction[]{roundTripTransaction(params, prevTx), roundTripTransaction(params,t)};
    }

    /**
     * Roundtrip a transaction so that it appears as if it has just come from the wire
     */
    public static Transaction roundTripTransaction(NetworkParameters params, Transaction tx) throws IOException, ProtocolException {
        BitcoinSerializer bs = new BitcoinSerializer(params);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bs.serialize(tx, bos);
        return (Transaction) bs.deserialize(ByteBuffer.wrap(bos.toByteArray()));
    }

    public static class DoubleSpends {
        public Transaction t1, t2, prevTx;
    }

    /**
     * Creates two transactions that spend the same (fake) output. t1 spends to "to". t2 spends somewhere else.
     * The fake output goes to the same address as t2.
     */
    public static DoubleSpends createFakeDoubleSpendTxns(NetworkParameters params, Address to) {
        DoubleSpends doubleSpends = new DoubleSpends();
        BigInteger value = Utils.toNanoCoins(1, 0);
        Address someBadGuy = new ECKey().toAddress(params);

        doubleSpends.t1 = new Transaction(params);
        TransactionOutput o1 = new TransactionOutput(params, doubleSpends.t1, value, to);
        doubleSpends.t1.addOutput(o1);

        doubleSpends.prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, doubleSpends.prevTx, value, someBadGuy);
        doubleSpends.prevTx.addOutput(prevOut);
        doubleSpends.t1.addInput(prevOut);

        doubleSpends.t2 = new Transaction(params);
        doubleSpends.t2.addInput(prevOut);
        TransactionOutput o2 = new TransactionOutput(params, doubleSpends.t2, value, someBadGuy);
        doubleSpends.t2.addOutput(o2);

        try {
            doubleSpends.t1 = new Transaction(params, doubleSpends.t1.bitcoinSerialize());
            doubleSpends.t2 = new Transaction(params, doubleSpends.t2.bitcoinSerialize());
        } catch (ProtocolException e) {
            throw new RuntimeException(e);
        }
        return doubleSpends;
    }

    public static class BlockPair {
        public StoredBlock storedBlock;
        public Block block;
    }

    // Emulates receiving a valid block that builds on top of the chain.
    public static BlockPair createFakeBlock(BlockStore blockStore, long timeSeconds, Transaction... transactions) {
        try {
            Block chainHead = blockStore.getChainHead().getHeader();
            Address to = new ECKey().toAddress(chainHead.getParams());
            Block b = chainHead.createNextBlock(to, timeSeconds);
            // Coinbase tx was already added.
            for (Transaction tx : transactions) {
                tx.getConfidence().setSource(TransactionConfidence.Source.NETWORK);
                b.addTransaction(tx);
            }
            b.solve();
            BlockPair pair = new BlockPair();
            pair.block = b;
            pair.storedBlock = blockStore.getChainHead().build(b);
            blockStore.put(pair.storedBlock);
            blockStore.setChainHead(pair.storedBlock);
            return pair;
        } catch (VerificationException e) {
            throw new RuntimeException(e);  // Cannot happen.
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    public static BlockPair createFakeBlock(BlockStore blockStore, Transaction... transactions) {
        return createFakeBlock(blockStore, Utils.currentTimeSeconds(), transactions);
    }

    public static Block makeSolvedTestBlock(BlockStore blockStore, Address coinsTo) throws BlockStoreException {
        Block b = blockStore.getChainHead().getHeader().createNextBlock(coinsTo);
        b.solve();
        return b;
    }

    public static Block makeSolvedTestBlock(Block prev, Transaction... transactions) throws BlockStoreException {
        Address to = new ECKey().toAddress(prev.getParams());
        Block b = prev.createNextBlock(to);
        // Coinbase tx already exists.
        for (Transaction tx : transactions) {
            b.addTransaction(tx);
        }
        b.solve();
        return b;
    }
}
