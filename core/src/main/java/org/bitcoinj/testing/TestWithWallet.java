/*
 * Copyright 2013 Google Inc.
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

import org.bitcoinj.core.*;
import org.bitcoinj.params.UnitTestParams;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.MemoryBlockStore;
import org.bitcoinj.utils.BriefLogFormatter;

import javax.annotation.Nullable;

import static org.bitcoinj.testing.FakeTxBuilder.createFakeBlock;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeTx;

// TODO: This needs to be somewhat rewritten - the "sendMoneyToWallet" methods aren't sending via the block chain object

/**
 * A utility class that you can derive from in your unit tests. TestWithWallet sets up a wallet with a key,
 * an in memory block store and a block chain object. It also provides helper methods for filling the wallet
 * with money in whatever ways you wish. Note that for simplicity with amounts, this class sets the default
 * fee per kilobyte to zero in setUp and back to normal in tearDown. If you are wanting to test your behaviour
 * with fees (a good idea!) make sure you set the {@link Wallet.SendRequest#DEFAULT_FEE_PER_KB} value to
 * {@link Transaction#REFERENCE_DEFAULT_MIN_TX_FEE} before doing so.
 */
public class TestWithWallet {
    protected static final NetworkParameters params = UnitTestParams.get();
    protected ECKey myKey;
    protected Address myAddress;
    protected Wallet wallet;
    protected BlockChain chain;
    protected BlockStore blockStore;

    public void setUp() throws Exception {
        BriefLogFormatter.init();
        Wallet.SendRequest.DEFAULT_FEE_PER_KB = Coin.ZERO;
        wallet = new Wallet(params);
        myKey = wallet.currentReceiveKey();
        myAddress = myKey.toAddress(params);
        blockStore = new MemoryBlockStore(params);
        chain = new BlockChain(params, wallet, blockStore);
    }

    public void tearDown() throws Exception {
        Wallet.SendRequest.DEFAULT_FEE_PER_KB = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE;
    }

    @Nullable
    protected Transaction sendMoneyToWallet(Wallet wallet, Transaction tx, AbstractBlockChain.NewBlockType type)
            throws VerificationException {
        if (type == null) {
            // Pending/broadcast tx.
            if (wallet.isPendingTransactionRelevant(tx))
                wallet.receivePending(tx, null);
        } else {
            FakeTxBuilder.BlockPair bp = createFakeBlock(blockStore, tx);
            wallet.receiveFromBlock(tx, bp.storedBlock, type, 0);
            if (type == AbstractBlockChain.NewBlockType.BEST_CHAIN)
                wallet.notifyNewBestBlock(bp.storedBlock);
        }
        return wallet.getTransaction(tx.getHash());  // Can be null if tx is a double spend that's otherwise irrelevant.
    }

    @Nullable
    protected Transaction sendMoneyToWallet(Transaction tx, AbstractBlockChain.NewBlockType type) throws VerificationException {
        return sendMoneyToWallet(this.wallet, tx, type);
    }

    @Nullable
    protected Transaction sendMoneyToWallet(Wallet wallet, Coin value, Address toAddress, AbstractBlockChain.NewBlockType type) throws VerificationException {
        return sendMoneyToWallet(wallet, createFakeTx(params, value, toAddress), type);
    }

    @Nullable
    protected Transaction sendMoneyToWallet(Wallet wallet, Coin value, ECKey toPubKey, AbstractBlockChain.NewBlockType type) throws VerificationException {
        return sendMoneyToWallet(wallet, createFakeTx(params, value, toPubKey), type);
    }

    @Nullable
    protected Transaction sendMoneyToWallet(Coin value, AbstractBlockChain.NewBlockType type) throws VerificationException {
        return sendMoneyToWallet(this.wallet, createFakeTx(params, value, myAddress), type);
    }
}
