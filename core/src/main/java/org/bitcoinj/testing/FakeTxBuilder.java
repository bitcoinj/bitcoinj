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
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.core.Block;
import org.bitcoinj.base.Coin;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.core.ProtocolException;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.StoredBlock;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutPoint;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;

import javax.annotation.Nullable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Random;

import static org.bitcoinj.base.Coin.COIN;
import static org.bitcoinj.base.Coin.valueOf;
import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * Methods for building fake transactions for unit tests. Since these methods are currently used both in the `bitcoinj-core`
 * unit tests and in the `integration-test` subproject, they are (for now) included in the `bitcoinj-core` JAR. They should
 * not be considered part of the API.
 */
@VisibleForTesting
public class FakeTxBuilder {
    /** Create a fake transaction, without change. */
    public static Transaction createFakeTx(Network network) {
        return createFakeTxWithoutChangeAddress(Coin.COIN, randomAddress(network));
    }

    /** Create a fake transaction, without change. */
    public static Transaction createFakeTxWithoutChange(final TransactionOutput output) {
        Transaction prevTx = FakeTxBuilder.createFakeTx(Coin.COIN, randomKey());
        Transaction tx = new Transaction();
        tx.addOutput(output);
        tx.addInput(prevTx.getOutput(0));
        return tx;
    }

    /** Create a fake coinbase transaction. */
    public static Transaction createFakeCoinbaseTx() {
        Transaction tx = Transaction.coinbase();
        TransactionOutput outputToMe = new TransactionOutput(tx, Coin.FIFTY_COINS, randomKey());
        checkState(tx.isCoinBase());
        tx.addOutput(outputToMe);
        return tx;
    }

    /**
     * Create a fake TX of sufficient realism to exercise the unit tests. Two outputs, one to us, one to somewhere
     * else to simulate change. There is one random input.
     */
    public static Transaction createFakeTxWithChangeAddress(Coin value, Address to, Address changeOutput) {
        Transaction t = new Transaction();
        TransactionOutput outputToMe = new TransactionOutput(t, value, to);
        t.addOutput(outputToMe);
        TransactionOutput change = new TransactionOutput(t, valueOf(1, 11), changeOutput);
        t.addOutput(change);
        // Make a previous tx simply to send us sufficient coins. This prev tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction prevTx = new Transaction();
        TransactionOutput prevOut = new TransactionOutput(prevTx, value, to);
        prevTx.addOutput(prevOut);
        // Connect it.
        t.addInput(prevOut).setScriptSig(ScriptBuilder.createInputScript(TransactionSignature.dummy()));
        // Fake signature.
        // Serialize/deserialize to ensure internal state is stripped, as if it had been read from the wire.
        return roundTripTransaction(t);
    }

    /**
     * Create a fake TX for unit tests, for use with unit tests that need greater control. One outputs, 2 random inputs,
     * split randomly to create randomness.
     */
    public static Transaction createFakeTxWithoutChangeAddress(Coin value, Address to) {
        Transaction t = new Transaction();
        TransactionOutput outputToMe = new TransactionOutput(t, value, to);
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
        Transaction prevTx1 = new Transaction();
        TransactionOutput prevOut1 = new TransactionOutput(prevTx1, Coin.valueOf(split), to);
        prevTx1.addOutput(prevOut1);
        // Connect it.
        t.addInput(prevOut1).setScriptSig(ScriptBuilder.createInputScript(TransactionSignature.dummy()));
        // Fake signature.

        // Do it again
        Transaction prevTx2 = new Transaction();
        TransactionOutput prevOut2 = new TransactionOutput(prevTx2, Coin.valueOf(value.getValue() - split), to);
        prevTx2.addOutput(prevOut2);
        t.addInput(prevOut2).setScriptSig(ScriptBuilder.createInputScript(TransactionSignature.dummy()));

        // Serialize/deserialize to ensure internal state is stripped, as if it had been read from the wire.
        return roundTripTransaction(t);
    }

    /**
     * Create a fake TX of sufficient realism to exercise the unit tests. Two outputs, one to us, one to somewhere
     * else to simulate change. There is one random input.
     */
    public static Transaction createFakeTx(Network network, Coin value, Address to) {
        return createFakeTxWithChangeAddress(value, to, randomAddress(network));
    }

    /**
     * Create a fake TX of sufficient realism to exercise the unit tests. Two outputs, one to us, one to somewhere
     * else to simulate change. There is one random input.
     */
    public static Transaction createFakeTx(Coin value, ECKey to) {
        Transaction t = new Transaction();
        TransactionOutput outputToMe = new TransactionOutput(t, value, to);
        t.addOutput(outputToMe);
        TransactionOutput change = new TransactionOutput(t, valueOf(1, 11), new ECKey());
        t.addOutput(change);
        // Make a previous tx simply to send us sufficient coins. This prev tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction prevTx = new Transaction();
        TransactionOutput prevOut = new TransactionOutput(prevTx, value, to);
        prevTx.addOutput(prevOut);
        // Connect it.
        t.addInput(prevOut);
        // Serialize/deserialize to ensure internal state is stripped, as if it had been read from the wire.
        return roundTripTransaction(t);
    }

    /**
     * Transaction[0] is a feeder transaction, supplying BTC to Transaction[1]
     */
    public static Transaction[] createFakeTx(Coin value, Address to, Address from) {
        // Create fake TXes of sufficient realism to exercise the unit tests. This transaction send BTC from the
        // from address, to the to address with to one to somewhere else to simulate change.
        Transaction t = new Transaction();
        TransactionOutput outputToMe = new TransactionOutput(t, value, to);
        t.addOutput(outputToMe);
        TransactionOutput change = new TransactionOutput(t, valueOf(1, 11), randomKey());
        t.addOutput(change);
        // Make a feeder tx that sends to the from address specified. This feeder tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction feederTx = new Transaction();
        TransactionOutput feederOut = new TransactionOutput(feederTx, value, from);
        feederTx.addOutput(feederOut);

        // make a previous tx that sends from the feeder to the from address
        Transaction prevTx = new Transaction();
        TransactionOutput prevOut = new TransactionOutput(prevTx, value, to);
        prevTx.addOutput(prevOut);

        // Connect up the txes
        prevTx.addInput(feederOut);
        t.addInput(prevOut);

        // roundtrip the tx so that they are just like they would be from the wire
        return new Transaction[]{roundTripTransaction(prevTx), roundTripTransaction(t)};
    }

    /**
     * Roundtrip a transaction so that it appears as if it has just come from the wire
     */
    public static Transaction roundTripTransaction(Transaction tx) {
        return Transaction.read(ByteBuffer.wrap(tx.serialize()));
    }

    public static class DoubleSpends {
        public Transaction t1, t2, prevTx;
    }

    /**
     * Creates two transactions that spend the same (fake) output. t1 spends to "to". t2 spends somewhere else.
     * The fake output goes to the same address as t2.
     */
    public static DoubleSpends createFakeDoubleSpendTxns(Address to) {
        DoubleSpends doubleSpends = new DoubleSpends();
        Coin value = COIN;
        ECKey someBadGuy = randomKey();

        doubleSpends.prevTx = new Transaction();
        TransactionOutput prevOut = new TransactionOutput(doubleSpends.prevTx, value, someBadGuy);
        doubleSpends.prevTx.addOutput(prevOut);

        doubleSpends.t1 = new Transaction();
        TransactionOutput o1 = new TransactionOutput(doubleSpends.t1, value, to);
        doubleSpends.t1.addOutput(o1);
        doubleSpends.t1.addInput(prevOut);

        doubleSpends.t2 = new Transaction();
        doubleSpends.t2.addInput(prevOut);
        TransactionOutput o2 = new TransactionOutput(doubleSpends.t2, value, someBadGuy);
        doubleSpends.t2.addOutput(o2);

        try {
            doubleSpends.t1 = roundTripTransaction(doubleSpends.t1);
            doubleSpends.t2 = roundTripTransaction(doubleSpends.t2);
        } catch (ProtocolException e) {
            throw new RuntimeException(e);
        }
        return doubleSpends;
    }

    public static class BlockPair {
        public final Block block;
        public final StoredBlock storedBlock;

        public BlockPair(Block block, StoredBlock storedBlock) {
            this.storedBlock = storedBlock;
            this.block = block;
        }
    }

    /** Emulates receiving a valid block that builds on top of the chain. */
    public static BlockPair createFakeBlock(BlockStore blockStore, long version,
                                            Instant time, Transaction... transactions) {
        return createFakeBlock(blockStore, version, time, 0, transactions);
    }

    /** Emulates receiving a valid block */
    public static BlockPair createFakeBlock(BlockStore blockStore, StoredBlock previousStoredBlock, long version,
                                            Instant time, int height, Transaction... transactions) {
        try {
            Block previousBlock = previousStoredBlock.getHeader();
            Block b = previousBlock.createNextBlock(null, version, time, height);
            // Coinbase tx was already added.
            for (Transaction tx : transactions) {
                tx.getConfidence().maybeSetSourceToNetwork();
                b.addTransaction(tx);
            }
            b.solve();
            BlockPair pair = new BlockPair(b, previousStoredBlock.build(b));
            blockStore.put(pair.storedBlock);
            blockStore.setChainHead(pair.storedBlock);
            return pair;
        } catch (VerificationException | BlockStoreException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    public static BlockPair createFakeBlock(BlockStore blockStore, StoredBlock previousStoredBlock, int height, Transaction... transactions) {
        return createFakeBlock(blockStore, previousStoredBlock, Block.BLOCK_VERSION_BIP66, TimeUtils.currentTime(), height, transactions);
    }

    /** Emulates receiving a valid block that builds on top of the chain. */
    public static BlockPair createFakeBlock(BlockStore blockStore, long version, Instant time, int height, Transaction... transactions) {
        try {
            return createFakeBlock(blockStore, blockStore.getChainHead(), version, time, height, transactions);
        } catch (BlockStoreException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /** Emulates receiving a valid block that builds on top of the chain. */
    public static BlockPair createFakeBlock(BlockStore blockStore, int height,
                                            Transaction... transactions) {
        return createFakeBlock(blockStore, Block.BLOCK_VERSION_GENESIS, TimeUtils.currentTime(), height, transactions);
    }

    /** Emulates receiving a valid block that builds on top of the chain. */
    public static BlockPair createFakeBlock(BlockStore blockStore, Transaction... transactions) {
        return createFakeBlock(blockStore, Block.BLOCK_VERSION_GENESIS, TimeUtils.currentTime(), 0, transactions);
    }

    public static Block makeSolvedTestBlock(BlockStore blockStore, Address coinsTo) throws BlockStoreException {
        Block b = blockStore.getChainHead().getHeader().createNextBlock(coinsTo);
        b.solve();
        return b;
    }

    public static Block makeSolvedTestBlock(Block prev, Transaction... transactions) throws BlockStoreException {
        return makeSolvedTestBlock(prev, null, transactions);
    }

    public static Block makeSolvedTestBlock(Block prev, @Nullable Address to, Transaction... transactions) throws BlockStoreException {
        Block b = prev.createNextBlock(to);
        // Coinbase tx already exists.
        for (Transaction tx : transactions) {
            b.addTransaction(tx);
        }
        b.solve();
        return b;
    }

    private static Address randomAddress(Network network) {
        return randomKey().toAddress(ScriptType.P2PKH, network);
    }

    private static ECKey randomKey() {
        return new ECKey();
    }
}
