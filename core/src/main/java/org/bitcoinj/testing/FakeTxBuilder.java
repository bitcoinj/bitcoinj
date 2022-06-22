/*
 * Copyright 2011 Google Inc.
 * Copyright 2016 Andreas Schildbach
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

package org.bitcoinj.testing;

import com.google.common.annotations.VisibleForTesting;
import org.bitcoinj.core.Address;
import org.bitcoinj.core.Block;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.MessageSerializer;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.ProtocolException;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Random;

import static com.google.common.base.Preconditions.checkState;
import static org.bitcoinj.base.Coin.COIN;
import static org.bitcoinj.base.Coin.valueOf;

/**
 * Methods for building fake transactions for unit tests. Since these methods are currently used both in the `bitcoinj-core`
 * unit tests and in the `integration-test` subproject, they are (for now) included in the `bitcoinj-core` JAR. They should
 * not be considered part of the API.
 */
@VisibleForTesting
public class FakeTxBuilder {
    /** Create a fake transaction, without change. */
    public static Transaction createFakeTx(final NetworkParameters params) {
        return createFakeTxWithoutChangeAddress(params, Coin.COIN, LegacyAddress.fromKey(params, new ECKey()));
    }

    /** Create a fake transaction, without change. */
    public static Transaction createFakeTxWithoutChange(final NetworkParameters params, final TransactionOutput output) {
        Transaction prevTx = FakeTxBuilder.createFakeTx(params, Coin.COIN, LegacyAddress.fromKey(params, new ECKey()));
        Transaction tx = new Transaction(params);
        tx.addOutput(output);
        tx.addInput(prevTx.getOutput(0));
        return tx;
    }

    /** Create a fake coinbase transaction. */
    public static Transaction createFakeCoinbaseTx(final NetworkParameters params) {
        TransactionOutPoint outpoint = new TransactionOutPoint(params, -1, Sha256Hash.ZERO_HASH);
        TransactionInput input = new TransactionInput(params, null, new byte[0], outpoint);
        Transaction tx = new Transaction(params);
        tx.addInput(input);
        TransactionOutput outputToMe = new TransactionOutput(params, tx, Coin.FIFTY_COINS,
                LegacyAddress.fromKey(params, new ECKey()));
        tx.addOutput(outputToMe);

        checkState(tx.isCoinBase());
        return tx;
    }

    /**
     * Create a fake TX of sufficient realism to exercise the unit tests. Two outputs, one to us, one to somewhere
     * else to simulate change. There is one random input.
     */
    public static Transaction createFakeTxWithChangeAddress(NetworkParameters params, Coin value, Address to, Address changeOutput) {
        Transaction t = new Transaction(params);
        TransactionOutput outputToMe = new TransactionOutput(params, t, value, to);
        t.addOutput(outputToMe);
        TransactionOutput change = new TransactionOutput(params, t, valueOf(1, 11), changeOutput);
        t.addOutput(change);
        // Make a previous tx simply to send us sufficient coins. This prev tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, prevTx, value, to);
        prevTx.addOutput(prevOut);
        // Connect it.
        t.addInput(prevOut).setScriptSig(ScriptBuilder.createInputScript(TransactionSignature.dummy()));
        // Fake signature.
        // Serialize/deserialize to ensure internal state is stripped, as if it had been read from the wire.
        return roundTripTransaction(params, t);
    }

    /**
     * Create a fake TX for unit tests, for use with unit tests that need greater control. One outputs, 2 random inputs,
     * split randomly to create randomness.
     */
    public static Transaction createFakeTxWithoutChangeAddress(NetworkParameters params, Coin value, Address to) {
        Transaction t = new Transaction(params);
        TransactionOutput outputToMe = new TransactionOutput(params, t, value, to);
        t.addOutput(outputToMe);

        // Make a random split in the output value so we get a distinct hash when we call this multiple times with same args
        long split = new Random().nextLong();
        if (split < 0) { split *= -1; }
        if (split == 0) { split = 15; }
        while (split > value.getValue()) {
            split /= 2;
        }

        // Make a previous tx simply to send us sufficient coins. This prev tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction prevTx1 = new Transaction(params);
        TransactionOutput prevOut1 = new TransactionOutput(params, prevTx1, Coin.valueOf(split), to);
        prevTx1.addOutput(prevOut1);
        // Connect it.
        t.addInput(prevOut1).setScriptSig(ScriptBuilder.createInputScript(TransactionSignature.dummy()));
        // Fake signature.

        // Do it again
        Transaction prevTx2 = new Transaction(params);
        TransactionOutput prevOut2 = new TransactionOutput(params, prevTx2, Coin.valueOf(value.getValue() - split), to);
        prevTx2.addOutput(prevOut2);
        t.addInput(prevOut2).setScriptSig(ScriptBuilder.createInputScript(TransactionSignature.dummy()));

        // Serialize/deserialize to ensure internal state is stripped, as if it had been read from the wire.
        return roundTripTransaction(params, t);
    }

    /**
     * Create a fake TX of sufficient realism to exercise the unit tests. Two outputs, one to us, one to somewhere
     * else to simulate change. There is one random input.
     */
    public static Transaction createFakeTx(NetworkParameters params, Coin value, Address to) {
        return createFakeTxWithChangeAddress(params, value, to, LegacyAddress.fromKey(params, new ECKey()));
    }

    /**
     * Create a fake TX of sufficient realism to exercise the unit tests. Two outputs, one to us, one to somewhere
     * else to simulate change. There is one random input.
     */
    public static Transaction createFakeTx(NetworkParameters params, Coin value, ECKey to) {
        Transaction t = new Transaction(params);
        TransactionOutput outputToMe = new TransactionOutput(params, t, value, to);
        t.addOutput(outputToMe);
        TransactionOutput change = new TransactionOutput(params, t, valueOf(1, 11), new ECKey());
        t.addOutput(change);
        // Make a previous tx simply to send us sufficient coins. This prev tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, prevTx, value, to);
        prevTx.addOutput(prevOut);
        // Connect it.
        t.addInput(prevOut);
        // Serialize/deserialize to ensure internal state is stripped, as if it had been read from the wire.
        return roundTripTransaction(params, t);
    }

    /**
     * Transaction[0] is a feeder transaction, supplying BTC to Transaction[1]
     */
    public static Transaction[] createFakeTx(NetworkParameters params, Coin value,
                                             Address to, Address from) {
        // Create fake TXes of sufficient realism to exercise the unit tests. This transaction send BTC from the
        // from address, to the to address with to one to somewhere else to simulate change.
        Transaction t = new Transaction(params);
        TransactionOutput outputToMe = new TransactionOutput(params, t, value, to);
        t.addOutput(outputToMe);
        TransactionOutput change = new TransactionOutput(params, t, valueOf(1, 11), LegacyAddress.fromKey(params, new ECKey()));
        t.addOutput(change);
        // Make a feeder tx that sends to the from address specified. This feeder tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction feederTx = new Transaction(params);
        TransactionOutput feederOut = new TransactionOutput(params, feederTx, value, from);
        feederTx.addOutput(feederOut);

        // make a previous tx that sends from the feeder to the from address
        Transaction prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, prevTx, value, to);
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
    public static Transaction roundTripTransaction(NetworkParameters params, Transaction tx) {
        try {
            MessageSerializer bs = params.getDefaultSerializer();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bs.serialize(tx, bos);
            return (Transaction) bs.deserialize(ByteBuffer.wrap(bos.toByteArray()));
        } catch (IOException e) {
            throw new RuntimeException(e);   // Should not happen.
        }
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
        Coin value = COIN;
        Address someBadGuy = LegacyAddress.fromKey(params, new ECKey());

        doubleSpends.prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, doubleSpends.prevTx, value, someBadGuy);
        doubleSpends.prevTx.addOutput(prevOut);

        doubleSpends.t1 = new Transaction(params);
        TransactionOutput o1 = new TransactionOutput(params, doubleSpends.t1, value, to);
        doubleSpends.t1.addOutput(o1);
        doubleSpends.t1.addInput(prevOut);

        doubleSpends.t2 = new Transaction(params);
        doubleSpends.t2.addInput(prevOut);
        TransactionOutput o2 = new TransactionOutput(params, doubleSpends.t2, value, someBadGuy);
        doubleSpends.t2.addOutput(o2);

        try {
            doubleSpends.t1 = params.getDefaultSerializer().makeTransaction(doubleSpends.t1.bitcoinSerialize());
            doubleSpends.t2 = params.getDefaultSerializer().makeTransaction(doubleSpends.t2.bitcoinSerialize());
        } catch (ProtocolException e) {
            throw new RuntimeException(e);
        }
        return doubleSpends;
    }

    public static class BlockPair {
        public StoredBlock storedBlock;
        public Block block;
    }

    /** Emulates receiving a valid block that builds on top of the chain. */
    public static BlockPair createFakeBlock(BlockStore blockStore, long version,
                                            long timeSeconds, Transaction... transactions) {
        return createFakeBlock(blockStore, version, timeSeconds, 0, transactions);
    }

    /** Emulates receiving a valid block */
    public static BlockPair createFakeBlock(BlockStore blockStore, StoredBlock previousStoredBlock, long version,
                                            long timeSeconds, int height,
                                            Transaction... transactions) {
        try {
            Block previousBlock = previousStoredBlock.getHeader();
            Address to = LegacyAddress.fromKey(previousBlock.getParams(), new ECKey());
            Block b = previousBlock.createNextBlock(to, version, timeSeconds, height);
            // Coinbase tx was already added.
            for (Transaction tx : transactions) {
                tx.getConfidence().setSource(TransactionConfidence.Source.NETWORK);
                b.addTransaction(tx);
            }
            b.solve();
            BlockPair pair = new BlockPair();
            pair.block = b;
            pair.storedBlock = previousStoredBlock.build(b);
            blockStore.put(pair.storedBlock);
            blockStore.setChainHead(pair.storedBlock);
            return pair;
        } catch (VerificationException | BlockStoreException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    public static BlockPair createFakeBlock(BlockStore blockStore, StoredBlock previousStoredBlock, int height, Transaction... transactions) {
        return createFakeBlock(blockStore, previousStoredBlock, Block.BLOCK_VERSION_BIP66, Utils.currentTimeSeconds(), height, transactions);
    }

    /** Emulates receiving a valid block that builds on top of the chain. */
    public static BlockPair createFakeBlock(BlockStore blockStore, long version, long timeSeconds, int height, Transaction... transactions) {
        try {
            return createFakeBlock(blockStore, blockStore.getChainHead(), version, timeSeconds, height, transactions);
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /** Emulates receiving a valid block that builds on top of the chain. */
    public static BlockPair createFakeBlock(BlockStore blockStore, int height,
                                            Transaction... transactions) {
        return createFakeBlock(blockStore, Block.BLOCK_VERSION_GENESIS, Utils.currentTimeSeconds(), height, transactions);
    }

    /** Emulates receiving a valid block that builds on top of the chain. */
    public static BlockPair createFakeBlock(BlockStore blockStore, Transaction... transactions) {
        return createFakeBlock(blockStore, Block.BLOCK_VERSION_GENESIS, Utils.currentTimeSeconds(), 0, transactions);
    }

    public static Block makeSolvedTestBlock(BlockStore blockStore, Address coinsTo) throws BlockStoreException {
        Block b = blockStore.getChainHead().getHeader().createNextBlock(coinsTo);
        b.solve();
        return b;
    }

    public static Block makeSolvedTestBlock(Block prev, Transaction... transactions) throws BlockStoreException {
        Address to = LegacyAddress.fromKey(prev.getParams(), new ECKey());
        Block b = prev.createNextBlock(to);
        // Coinbase tx already exists.
        for (Transaction tx : transactions) {
            b.addTransaction(tx);
        }
        b.solve();
        return b;
    }

    public static Block makeSolvedTestBlock(Block prev, Address to, Transaction... transactions) throws BlockStoreException {
        Block b = prev.createNextBlock(to);
        // Coinbase tx already exists.
        for (Transaction tx : transactions) {
            b.addTransaction(tx);
        }
        b.solve();
        return b;
    }
}
