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

import com.google.bitcoin.store.BlockStore;
import com.google.bitcoin.store.BlockStoreException;

import java.math.BigInteger;

public class TestUtils {
    public static Transaction createFakeTx(NetworkParameters params, BigInteger nanocoins, Address to) {
        // Create a fake TX of sufficient realism to exercise the unit tests. Two outputs, one to us, one to somewhere
        // else to simulate change.
        Transaction t = new Transaction(params);
        TransactionOutput outputToMe = new TransactionOutput(params, t, nanocoins, to);
        t.addOutput(outputToMe);
        TransactionOutput change = new TransactionOutput(params, t, Utils.toNanoCoins(1, 11), 
                new ECKey().toAddress(params));
        t.addOutput(change);
        // Make a previous tx simply to send us sufficient coins. This prev tx is not really valid but it doesn't
        // matter for our purposes.
        Transaction prevTx = new Transaction(params);
        TransactionOutput prevOut = new TransactionOutput(params, prevTx, nanocoins, to);
        prevTx.addOutput(prevOut);
        // Connect it.
        t.addInput(prevOut);
        return t;
    }

    public static class BlockPair {
        StoredBlock storedBlock;
        Block block;
    }

    // Emulates receiving a valid block that builds on top of the chain.
    public static BlockPair createFakeBlock(NetworkParameters params, BlockStore blockStore, long timeSeconds,
                                            Transaction... transactions) {
        try {
            Block b = blockStore.getChainHead().getHeader().createNextBlock(new ECKey().toAddress(params), timeSeconds);
            // Coinbase tx was already added.
            for (Transaction tx : transactions)
                b.addTransaction(tx);
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

    public static BlockPair createFakeBlock(NetworkParameters params, BlockStore blockStore,
                                            Transaction... transactions) {
        return createFakeBlock(params, blockStore, Utils.now().getTime() / 1000, transactions);
    }

    public static Block makeSolvedTestBlock(NetworkParameters params,
                                            BlockStore blockStore,
                                            Address coinsTo) throws BlockStoreException {
        Block b = blockStore.getChainHead().getHeader().createNextBlock(coinsTo);
        b.solve();
        return b;
    }

    public static Block makeSolvedTestBlock(NetworkParameters params,
                                            BlockStore blockStore) throws BlockStoreException {
        return makeSolvedTestBlock(params, blockStore, new ECKey().toAddress(params));
    }

    public static Block makeSolvedTestBlock(NetworkParameters params,
                                            Block prev) throws BlockStoreException {
        Block b = prev.createNextBlock(new ECKey().toAddress(params));
        b.solve();
        return b;
    }
}
