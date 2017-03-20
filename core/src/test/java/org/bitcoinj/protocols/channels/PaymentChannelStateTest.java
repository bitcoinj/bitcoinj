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

package org.bitcoinj.protocols.channels;

import org.bitcoinj.core.*;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.testing.TestWithWallet;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;

import com.google.common.collect.Lists;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;

import static org.bitcoinj.core.Coin.*;
import static org.bitcoinj.testing.FakeTxBuilder.createFakeTx;
import static org.bitcoinj.testing.FakeTxBuilder.makeSolvedTestBlock;
import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class PaymentChannelStateTest extends TestWithWallet {
    private ECKey serverKey;
    private Wallet serverWallet;
    private PaymentChannelServerState serverState;
    private PaymentChannelClientState clientState;
    private TransactionBroadcaster mockBroadcaster;
    private BlockingQueue<TxFuturePair> broadcasts;
    private static final Coin HALF_COIN = Coin.valueOf(0, 50);

    /**
     * We use parameterized tests to run the channel connection tests with each
     * version of the channel.
     */
    @Parameterized.Parameters(name = "{index}: PaymentChannelStateTest({0})")
    public static Collection<PaymentChannelClient.VersionSelector> data() {
        return Arrays.asList(
                PaymentChannelClient.VersionSelector.VERSION_1,
                PaymentChannelClient.VersionSelector.VERSION_2_ALLOW_1);
    }

    @Parameterized.Parameter
    public PaymentChannelClient.VersionSelector versionSelector;

    /**
     * Returns <code>true</code> if we are using a protocol version that requires the exchange of refunds.
     */
    private boolean useRefunds() {
        return versionSelector == PaymentChannelClient.VersionSelector.VERSION_1;
    }

    private static class TxFuturePair {
        Transaction tx;
        SettableFuture<Transaction> future;

        public TxFuturePair(Transaction tx, SettableFuture<Transaction> future) {
            this.tx = tx;
            this.future = future;
        }
    }

    @Override
    @Before
    public void setUp() throws Exception {
        Utils.setMockClock(); // Use mock clock
        super.setUp();
        Context.propagate(new Context(PARAMS, 100, Coin.ZERO, false));
        wallet.addExtension(new StoredPaymentChannelClientStates(wallet, new TransactionBroadcaster() {
            @Override
            public TransactionBroadcast broadcastTransaction(Transaction tx) {
                fail();
                return null;
            }
        }));
        sendMoneyToWallet(AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN);
        chain = new BlockChain(PARAMS, wallet, blockStore); // Recreate chain as sendMoneyToWallet will confuse it
        serverWallet = new Wallet(PARAMS);
        serverKey = serverWallet.freshReceiveKey();
        chain.addWallet(serverWallet);

        broadcasts = new LinkedBlockingQueue<>();
        mockBroadcaster = new TransactionBroadcaster() {
            @Override
            public TransactionBroadcast broadcastTransaction(Transaction tx) {
                SettableFuture<Transaction> future = SettableFuture.create();
                broadcasts.add(new TxFuturePair(tx, future));
                return TransactionBroadcast.createMockBroadcast(tx, future);
            }
        };
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }

    private PaymentChannelClientState makeClientState(Wallet wallet, ECKey myKey, ECKey serverKey, Coin value, long time) {
        switch (versionSelector) {
            case VERSION_1:
                return new PaymentChannelV1ClientState(wallet, myKey, serverKey, value, time);
            case VERSION_2_ALLOW_1:
            case VERSION_2:
                return new PaymentChannelV2ClientState(wallet, myKey, serverKey, value, time);
            default:
                return null;
        }
    }

    private PaymentChannelServerState makeServerState(TransactionBroadcaster broadcaster, Wallet wallet, ECKey serverKey, long time) {
        switch (versionSelector) {
            case VERSION_1:
                return new PaymentChannelV1ServerState(broadcaster, wallet, serverKey, time);
            case VERSION_2_ALLOW_1:
            case VERSION_2:
                return new PaymentChannelV2ServerState(broadcaster, wallet, serverKey, time);
            default:
                return null;
        }
    }

    private PaymentChannelV1ClientState clientV1State() {
        if (clientState instanceof PaymentChannelV1ClientState) {
            return (PaymentChannelV1ClientState) clientState;
        } else {
            return null;
        }
    }

    private PaymentChannelV1ServerState serverV1State() {
        if (serverState instanceof PaymentChannelV1ServerState) {
            return (PaymentChannelV1ServerState) serverState;
        } else {
            return null;
        }
    }

    private PaymentChannelV2ClientState clientV2State() {
        if (clientState instanceof PaymentChannelV2ClientState) {
            return (PaymentChannelV2ClientState) clientState;
        } else {
            return null;
        }
    }

    private PaymentChannelV2ServerState serverV2State() {
        if (serverState instanceof PaymentChannelV2ServerState) {
            return (PaymentChannelV2ServerState) serverState;
        } else {
            return null;
        }
    }

    private PaymentChannelServerState.State getInitialServerState() {
        switch (versionSelector) {
            case VERSION_1:
                return PaymentChannelServerState.State.WAITING_FOR_REFUND_TRANSACTION;
            case VERSION_2_ALLOW_1:
            case VERSION_2:
                return PaymentChannelServerState.State.WAITING_FOR_MULTISIG_CONTRACT;
            default:
                return null;
        }
    }

    private PaymentChannelClientState.State getInitialClientState() {
        switch (versionSelector) {
            case VERSION_1:
                return PaymentChannelClientState.State.INITIATED;
            case VERSION_2_ALLOW_1:
            case VERSION_2:
                return PaymentChannelClientState.State.SAVE_STATE_IN_WALLET;
            default:
                return null;
        }
    }

    @Test
    public void stateErrors() throws Exception {
        PaymentChannelClientState channelState = makeClientState(wallet, myKey, serverKey,
                COIN.multiply(10), 20);
        assertEquals(PaymentChannelClientState.State.NEW, channelState.getState());
        try {
            channelState.getContract();
            fail();
        } catch (IllegalStateException e) {
            // Expected.
        }
        try {
            channelState.initiate();
            fail();
        } catch (InsufficientMoneyException e) {
        }
    }

    @Test
    public void basic() throws Exception {
        // Check it all works when things are normal (no attacks, no problems).
        Utils.setMockClock(); // Use mock clock
        final long EXPIRE_TIME = Utils.currentTimeSeconds() + 60*60*24;

        serverState = makeServerState(mockBroadcaster, serverWallet, serverKey, EXPIRE_TIME);
        assertEquals(getInitialServerState(), serverState.getState());

        clientState = makeClientState(wallet, myKey, ECKey.fromPublicOnly(serverKey.getPubKey()), HALF_COIN, EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        clientState.initiate();
        assertEquals(getInitialClientState(), clientState.getState());

        // Send the refund tx from client to server and get back the signature.
        Transaction refund;
        if (useRefunds()) {
            refund = new Transaction(PARAMS, clientV1State().getIncompleteRefundTransaction().bitcoinSerialize());
            byte[] refundSig = serverV1State().provideRefundTransaction(refund, myKey.getPubKey());
            assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_CONTRACT, serverState.getState());
            // This verifies that the refund can spend the multi-sig output when run.
            clientV1State().provideRefundSignature(refundSig, null);
        } else {
            refund = clientV2State().getRefundTransaction();
        }
        assertEquals(PaymentChannelClientState.State.SAVE_STATE_IN_WALLET, clientState.getState());
        clientState.fakeSave();
        assertEquals(PaymentChannelClientState.State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER, clientState.getState());

        // Validate the multisig contract looks right.
        Transaction multisigContract = new Transaction(PARAMS, clientState.getContract().bitcoinSerialize());
        assertEquals(PaymentChannelClientState.State.READY, clientState.getState());
        assertEquals(2, multisigContract.getOutputs().size());   // One multi-sig, one change.
        Script script = multisigContract.getOutput(0).getScriptPubKey();
        if (versionSelector == PaymentChannelClient.VersionSelector.VERSION_1) {
            assertTrue(script.isSentToMultiSig());
        } else {
            assertTrue(script.isPayToScriptHash());
        }
        script = multisigContract.getOutput(1).getScriptPubKey();
        assertTrue(script.isSentToAddress());
        assertTrue(wallet.getPendingTransactions().contains(multisigContract));

        // Provide the server with the multisig contract and simulate successful propagation/acceptance.
        if (!useRefunds()) {
            serverV2State().provideClientKey(clientState.myKey.getPubKey());
        }
        serverState.provideContract(multisigContract);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_ACCEPTANCE, serverState.getState());
        final TxFuturePair pair = broadcasts.take();
        pair.future.set(pair.tx);
        assertEquals(PaymentChannelServerState.State.READY, serverState.getState());

        // Make sure the refund transaction is not in the wallet and multisig contract's output is not connected to it
        assertEquals(2, wallet.getTransactions(false).size());
        Iterator<Transaction> walletTransactionIterator = wallet.getTransactions(false).iterator();
        Transaction clientWalletMultisigContract = walletTransactionIterator.next();
        assertFalse(clientWalletMultisigContract.getHash().equals(clientState.getRefundTransaction().getHash()));
        if (!clientWalletMultisigContract.getHash().equals(multisigContract.getHash())) {
            clientWalletMultisigContract = walletTransactionIterator.next();
            assertFalse(clientWalletMultisigContract.getHash().equals(clientState.getRefundTransaction().getHash()));
        } else
            assertFalse(walletTransactionIterator.next().getHash().equals(clientState.getRefundTransaction().getHash()));
        assertEquals(multisigContract.getHash(), clientWalletMultisigContract.getHash());
        assertFalse(clientWalletMultisigContract.getInput(0).getConnectedOutput().getSpentBy().getParentTransaction().getHash().equals(refund.getHash()));

        // Both client and server are now in the ready state. Simulate a few micropayments of 0.005 bitcoins.
        Coin size = HALF_COIN.divide(100);
        Coin totalPayment = Coin.ZERO;
        for (int i = 0; i < 4; i++) {
            byte[] signature = clientState.incrementPaymentBy(size, null).signature.encodeToBitcoin();
            totalPayment = totalPayment.add(size);
            serverState.incrementPayment(HALF_COIN.subtract(totalPayment), signature);
        }

        // Now confirm the contract transaction and make sure payments still work
        chain.add(makeSolvedTestBlock(blockStore.getChainHead().getHeader(), multisigContract));

        byte[] signature = clientState.incrementPaymentBy(size, null).signature.encodeToBitcoin();
        totalPayment = totalPayment.add(size);
        serverState.incrementPayment(HALF_COIN.subtract(totalPayment), signature);

        // And settle the channel.
        serverState.close();
        assertEquals(PaymentChannelServerState.State.CLOSING, serverState.getState());
        final TxFuturePair pair2 = broadcasts.take();
        Transaction closeTx = pair2.tx;
        pair2.future.set(closeTx);
        final Transaction reserializedCloseTx = new Transaction(PARAMS, closeTx.bitcoinSerialize());
        assertEquals(PaymentChannelServerState.State.CLOSED, serverState.getState());
        // ... and on the client side.
        wallet.receivePending(reserializedCloseTx, null);
        assertEquals(PaymentChannelClientState.State.CLOSED, clientState.getState());

        // Create a block with the payment transaction in it and give it to both wallets
        chain.add(makeSolvedTestBlock(blockStore.getChainHead().getHeader(), reserializedCloseTx));

        assertEquals(size.multiply(5), serverWallet.getBalance());
        assertEquals(0, serverWallet.getPendingTransactions().size());

        assertEquals(COIN.subtract(size.multiply(5)), wallet.getBalance());
        assertEquals(0, wallet.getPendingTransactions().size());
        assertEquals(3, wallet.getTransactions(false).size());

        walletTransactionIterator = wallet.getTransactions(false).iterator();
        Transaction clientWalletCloseTransaction = walletTransactionIterator.next();
        if (!clientWalletCloseTransaction.getHash().equals(closeTx.getHash()))
            clientWalletCloseTransaction = walletTransactionIterator.next();
        if (!clientWalletCloseTransaction.getHash().equals(closeTx.getHash()))
            clientWalletCloseTransaction = walletTransactionIterator.next();
        assertEquals(closeTx.getHash(), clientWalletCloseTransaction.getHash());
        assertNotNull(clientWalletCloseTransaction.getInput(0).getConnectedOutput());
    }

    @Test
    public void setupDoS() throws Exception {
        // Check that if the other side stops after we have provided a signed multisig contract, that after a timeout
        // we can broadcast the refund and get our balance back.

        // Spend the client wallet's one coin
        Transaction spendCoinTx = wallet.sendCoinsOffline(SendRequest.to(new ECKey().toAddress(PARAMS), COIN));
        assertEquals(Coin.ZERO, wallet.getBalance());
        chain.add(makeSolvedTestBlock(blockStore.getChainHead().getHeader(), spendCoinTx, createFakeTx(PARAMS, CENT, myAddress)));
        assertEquals(CENT, wallet.getBalance());

        // Set the wallet's stored states to use our real test PeerGroup
        StoredPaymentChannelClientStates stateStorage = new StoredPaymentChannelClientStates(wallet, mockBroadcaster);
        wallet.addOrUpdateExtension(stateStorage);

        Utils.setMockClock(); // Use mock clock
        final long EXPIRE_TIME = Utils.currentTimeMillis()/1000 + 60*60*24;

        serverState = makeServerState(mockBroadcaster, serverWallet, serverKey, EXPIRE_TIME);
        assertEquals(getInitialServerState(), serverState.getState());

        clientState = makeClientState(wallet, myKey, ECKey.fromPublicOnly(serverKey.getPubKey()),
                                                    CENT.divide(2), EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        assertEquals(CENT.divide(2), clientState.getTotalValue());
        clientState.initiate();
        assertEquals(getInitialClientState(), clientState.getState());

        if (useRefunds()) {
            // Send the refund tx from client to server and get back the signature.
            Transaction refund = new Transaction(PARAMS, clientV1State().getIncompleteRefundTransaction().bitcoinSerialize());
            byte[] refundSig = serverV1State().provideRefundTransaction(refund, myKey.getPubKey());
            assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_CONTRACT, serverState.getState());
            // This verifies that the refund can spend the multi-sig output when run.
            clientV1State().provideRefundSignature(refundSig, null);
        }
        assertEquals(PaymentChannelClientState.State.SAVE_STATE_IN_WALLET, clientState.getState());
        clientState.fakeSave();
        assertEquals(PaymentChannelClientState.State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER, clientState.getState());

        // Validate the multisig contract looks right.
        Transaction multisigContract = new Transaction(PARAMS, clientState.getContract().bitcoinSerialize());
        assertEquals(PaymentChannelClientState.State.READY, clientState.getState());
        assertEquals(2, multisigContract.getOutputs().size());   // One multi-sig, one change.
        Script script = multisigContract.getOutput(0).getScriptPubKey();
        if (versionSelector == PaymentChannelClient.VersionSelector.VERSION_1) {
            assertTrue(script.isSentToMultiSig());
        } else {
            assertTrue(script.isPayToScriptHash());
        }
        script = multisigContract.getOutput(1).getScriptPubKey();
        assertTrue(script.isSentToAddress());
        assertTrue(wallet.getPendingTransactions().contains(multisigContract));

        // Provide the server with the multisig contract and simulate successful propagation/acceptance.
        if (!useRefunds()) {
            serverV2State().provideClientKey(clientState.myKey.getPubKey());
        }
        serverState.provideContract(multisigContract);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_ACCEPTANCE, serverState.getState());
        final TxFuturePair pop = broadcasts.take();
        pop.future.set(pop.tx);
        assertEquals(PaymentChannelServerState.State.READY, serverState.getState());

        // Pay a tiny bit
        serverState.incrementPayment(CENT.divide(2).subtract(CENT.divide(10)),
                clientState.incrementPaymentBy(CENT.divide(10), null).signature.encodeToBitcoin());

        // Advance time until our we get close enough to lock time that server should rebroadcast
        Utils.rollMockClock(60*60*22);
        // ... and store server to get it to broadcast payment transaction
        serverState.storeChannelInWallet(null);
        TxFuturePair broadcastPaymentPair = broadcasts.take();
        Exception paymentException = new RuntimeException("I'm sorry, but the network really just doesn't like you");
        broadcastPaymentPair.future.setException(paymentException);
        try {
            serverState.close().get();
        } catch (ExecutionException e) {
            assertSame(e.getCause(), paymentException);
        }
        assertEquals(PaymentChannelServerState.State.ERROR, serverState.getState());

        // Now advance until client should rebroadcast
        Utils.rollMockClock(60 * 60 * 2 + 60 * 5);

        // Now store the client state in a stored state object which handles the rebroadcasting
        clientState.doStoreChannelInWallet(Sha256Hash.of(new byte[]{}));
        TxFuturePair clientBroadcastedMultiSig = broadcasts.take();
        TxFuturePair broadcastRefund = broadcasts.take();
        assertEquals(clientBroadcastedMultiSig.tx.getHash(), multisigContract.getHash());
        for (TransactionInput input : clientBroadcastedMultiSig.tx.getInputs())
            input.verify();
        clientBroadcastedMultiSig.future.set(clientBroadcastedMultiSig.tx);

        Transaction clientBroadcastedRefund = broadcastRefund.tx;
        assertEquals(clientBroadcastedRefund.getHash(), clientState.getRefundTransaction().getHash());
        for (TransactionInput input : clientBroadcastedRefund.getInputs()) {
            // If the multisig output is connected, the wallet will fail to deserialize
            if (input.getOutpoint().getHash().equals(clientBroadcastedMultiSig.tx.getHash()))
                assertNull(input.getConnectedOutput().getSpentBy());
            input.verify(clientBroadcastedMultiSig.tx.getOutput(0));
        }
        broadcastRefund.future.set(clientBroadcastedRefund);

        // Create a block with multisig contract and refund transaction in it and give it to both wallets,
        // making getBalance() include the transactions
        chain.add(makeSolvedTestBlock(blockStore.getChainHead().getHeader(), multisigContract,clientBroadcastedRefund));

        // Make sure we actually had to pay what initialize() told us we would
        assertEquals(CENT, wallet.getBalance());

        try {
            // After its expired, we cant still increment payment
            clientState.incrementPaymentBy(CENT, null);
            fail();
        } catch (IllegalStateException e) { }
    }

    @Test
    public void checkBadData() throws Exception {
        // Check that if signatures/transactions/etc are corrupted, the protocol rejects them correctly.

        // We'll broadcast only one tx: multisig contract
        Utils.setMockClock(); // Use mock clock
        final long EXPIRE_TIME = Utils.currentTimeSeconds() + 60*60*24;

        serverState = makeServerState(mockBroadcaster, serverWallet, serverKey, EXPIRE_TIME);
        assertEquals(getInitialServerState(), serverState.getState());

        clientState = makeClientState(wallet, myKey, ECKey.fromPublicOnly(serverKey.getPubKey()), HALF_COIN, EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        clientState.initiate();
        assertEquals(getInitialClientState(), clientState.getState());

        if (useRefunds()) {
            // Test refund transaction with any number of issues
            byte[] refundTxBytes = clientV1State().getIncompleteRefundTransaction().bitcoinSerialize();
            Transaction refund = new Transaction(PARAMS, refundTxBytes);
            refund.addOutput(Coin.ZERO, new ECKey().toAddress(PARAMS));
            try {
                serverV1State().provideRefundTransaction(refund, myKey.getPubKey());
                fail();
            } catch (VerificationException e) {
            }

            refund = new Transaction(PARAMS, refundTxBytes);
            refund.addInput(new TransactionInput(PARAMS, refund, new byte[]{}, new TransactionOutPoint(PARAMS, 42, refund.getHash())));
            try {
                serverV1State().provideRefundTransaction(refund, myKey.getPubKey());
                fail();
            } catch (VerificationException e) {
            }

            refund = new Transaction(PARAMS, refundTxBytes);
            refund.setLockTime(0);
            try {
                serverV1State().provideRefundTransaction(refund, myKey.getPubKey());
                fail();
            } catch (VerificationException e) {
            }

            refund = new Transaction(PARAMS, refundTxBytes);
            refund.getInput(0).setSequenceNumber(TransactionInput.NO_SEQUENCE);
            try {
                serverV1State().provideRefundTransaction(refund, myKey.getPubKey());
                fail();
            } catch (VerificationException e) {
            }

            refund = new Transaction(PARAMS, refundTxBytes);
            byte[] refundSig = serverV1State().provideRefundTransaction(refund, myKey.getPubKey());
            try {
                serverV1State().provideRefundTransaction(refund, myKey.getPubKey());
                fail();
            } catch (IllegalStateException e) {
            }
            assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_CONTRACT, serverState.getState());

            byte[] refundSigCopy = Arrays.copyOf(refundSig, refundSig.length);
            refundSigCopy[refundSigCopy.length - 1] = Transaction.SigHash.NONE.byteValue();
            try {
                clientV1State().provideRefundSignature(refundSigCopy, null);
                fail();
            } catch (VerificationException e) {
                assertTrue(e.getMessage().contains("SIGHASH_NONE"));
            }

            refundSigCopy = Arrays.copyOf(refundSig, refundSig.length);
            refundSigCopy[3] ^= 0x42; // Make the signature fail standard checks
            try {
                clientV1State().provideRefundSignature(refundSigCopy, null);
                fail();
            } catch (VerificationException e) {
                assertTrue(e.getMessage().contains("not canonical"));
            }

            refundSigCopy = Arrays.copyOf(refundSig, refundSig.length);
            refundSigCopy[10] ^= 0x42; // Flip some random bits in the signature (to make it invalid, not just nonstandard)
            try {
                clientV1State().provideRefundSignature(refundSigCopy, null);
                fail();
            } catch (VerificationException e) {
                assertFalse(e.getMessage().contains("not canonical"));
            }

            refundSigCopy = Arrays.copyOf(refundSig, refundSig.length);
            try {
                clientV1State().getCompletedRefundTransaction();
                fail();
            } catch (IllegalStateException e) {
            }
            clientV1State().provideRefundSignature(refundSigCopy, null);
            try {
                clientV1State().provideRefundSignature(refundSigCopy, null);
                fail();
            } catch (IllegalStateException e) {
            }
        }
        assertEquals(PaymentChannelClientState.State.SAVE_STATE_IN_WALLET, clientState.getState());
        clientState.fakeSave();
        assertEquals(PaymentChannelClientState.State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER, clientState.getState());

        if (!useRefunds()) {
            serverV2State().provideClientKey(myKey.getPubKey());
        }

        try { clientState.incrementPaymentBy(Coin.SATOSHI, null); fail(); } catch (IllegalStateException e) {}

        byte[] multisigContractSerialized = clientState.getContract().bitcoinSerialize();

        Transaction multisigContract = new Transaction(PARAMS, multisigContractSerialized);
        multisigContract.clearOutputs();
        // Swap order of client and server keys to check correct failure
        if (versionSelector == PaymentChannelClient.VersionSelector.VERSION_1) {
            multisigContract.addOutput(HALF_COIN, ScriptBuilder.createMultiSigOutputScript(2, Lists.newArrayList(serverKey, myKey)));
        } else {
            multisigContract.addOutput(HALF_COIN,
                    ScriptBuilder.createP2SHOutputScript(
                            ScriptBuilder.createCLTVPaymentChannelOutput(BigInteger.valueOf(serverState.getExpiryTime()), serverKey, myKey)));
        }
        try {
            serverState.provideContract(multisigContract);
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("client and server in that order"));
        }

        multisigContract = new Transaction(PARAMS, multisigContractSerialized);
        multisigContract.clearOutputs();
        if (versionSelector == PaymentChannelClient.VersionSelector.VERSION_1) {
            multisigContract.addOutput(Coin.ZERO, ScriptBuilder.createMultiSigOutputScript(2, Lists.newArrayList(myKey, serverKey)));
        } else {
            multisigContract.addOutput(Coin.ZERO,
                    ScriptBuilder.createP2SHOutputScript(
                            ScriptBuilder.createCLTVPaymentChannelOutput(BigInteger.valueOf(serverState.getExpiryTime()), myKey, serverKey)));
        }
        try {
            serverState.provideContract(multisigContract);
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("zero value"));
        }

        multisigContract = new Transaction(PARAMS, multisigContractSerialized);
        multisigContract.clearOutputs();
        multisigContract.addOutput(new TransactionOutput(PARAMS, multisigContract, HALF_COIN, new byte[] {0x01}));
        try {
            serverState.provideContract(multisigContract);
            fail();
        } catch (VerificationException e) {}

        multisigContract = new Transaction(PARAMS, multisigContractSerialized);
        ListenableFuture<PaymentChannelServerState> multisigStateFuture = serverState.provideContract(multisigContract);
        try { serverState.provideContract(multisigContract); fail(); } catch (IllegalStateException e) {}
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_ACCEPTANCE, serverState.getState());
        assertFalse(multisigStateFuture.isDone());
        final TxFuturePair pair = broadcasts.take();
        pair.future.set(pair.tx);
        assertEquals(multisigStateFuture.get(), serverState);
        assertEquals(PaymentChannelServerState.State.READY, serverState.getState());

        // Both client and server are now in the ready state. Simulate a few micropayments of 0.005 bitcoins.
        Coin size = HALF_COIN.divide(100);
        Coin totalPayment = Coin.ZERO;
        try {
            clientState.incrementPaymentBy(COIN, null);
            fail();
        } catch (ValueOutOfRangeException e) {}

        byte[] signature = clientState.incrementPaymentBy(size, null).signature.encodeToBitcoin();
        totalPayment = totalPayment.add(size);

        byte[] signatureCopy = Arrays.copyOf(signature, signature.length);
        signatureCopy[signatureCopy.length - 1] = Transaction.SigHash.ANYONECANPAY_NONE.byteValue();
        try {
            serverState.incrementPayment(HALF_COIN.subtract(totalPayment), signatureCopy);
            fail();
        } catch (VerificationException e) {}

        signatureCopy = Arrays.copyOf(signature, signature.length);
        signatureCopy[2]  ^= 0x42; // Make the signature fail standard checks
        try {
            serverState.incrementPayment(HALF_COIN.subtract(totalPayment), signatureCopy);
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("not canonical"));
        }

        signatureCopy = Arrays.copyOf(signature, signature.length);
        signatureCopy[10]  ^= 0x42; // Flip some random bits in the signature (to make it invalid, not just nonstandard)
        try {
            serverState.incrementPayment(HALF_COIN.subtract(totalPayment), signatureCopy);
            fail();
        } catch (VerificationException e) {
            assertFalse(e.getMessage().contains("not canonical"));
        }

        serverState.incrementPayment(HALF_COIN.subtract(totalPayment), signature);

        // Pay the rest (signed with SIGHASH_NONE|SIGHASH_ANYONECANPAY)
        byte[] signature2 = clientState.incrementPaymentBy(HALF_COIN.subtract(totalPayment), null).signature.encodeToBitcoin();
        totalPayment = totalPayment.add(HALF_COIN.subtract(totalPayment));
        assertEquals(totalPayment, HALF_COIN);

        signatureCopy = Arrays.copyOf(signature, signature.length);
        signatureCopy[signatureCopy.length - 1] = Transaction.SigHash.ANYONECANPAY_SINGLE.byteValue();
        try {
            serverState.incrementPayment(HALF_COIN.subtract(totalPayment), signatureCopy);
            fail();
        } catch (VerificationException e) {}

        serverState.incrementPayment(HALF_COIN.subtract(totalPayment), signature2);

        // Trying to take reduce the refund size fails.
        try {
            serverState.incrementPayment(HALF_COIN.subtract(totalPayment.subtract(size)), signature);
            fail();
        } catch (ValueOutOfRangeException e) {}
        assertEquals(serverState.getBestValueToMe(), totalPayment);

        try {
            clientState.incrementPaymentBy(Coin.SATOSHI.negate(), null);
            fail();
        } catch (ValueOutOfRangeException e) {}

        try {
            clientState.incrementPaymentBy(HALF_COIN.subtract(size).add(Coin.SATOSHI), null);
            fail();
        } catch (ValueOutOfRangeException e) {}
    }

    @Test
    public void feesTest() throws Exception {
        // Test that transactions are getting the necessary fees
        Context.propagate(new Context(PARAMS, 100, Coin.ZERO, true));

        // Spend the client wallet's one coin
        final SendRequest request = SendRequest.to(new ECKey().toAddress(PARAMS), COIN);
        request.ensureMinRequiredFee = false;
        wallet.sendCoinsOffline(request);
        assertEquals(Coin.ZERO, wallet.getBalance());

        chain.add(makeSolvedTestBlock(blockStore.getChainHead().getHeader(),
                createFakeTx(PARAMS, CENT.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE), myAddress)));
        assertEquals(CENT.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE), wallet.getBalance());

        Utils.setMockClock(); // Use mock clock
        final long EXPIRE_TIME = Utils.currentTimeMillis()/1000 + 60*60*24;

        serverState = makeServerState(mockBroadcaster, serverWallet, serverKey, EXPIRE_TIME);
        assertEquals(getInitialServerState(), serverState.getState());

        // Clearly SATOSHI is far too small to be useful
        clientState = makeClientState(wallet, myKey, ECKey.fromPublicOnly(serverKey.getPubKey()), Coin.SATOSHI, EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        try {
            clientState.initiate();
            fail();
        } catch (ValueOutOfRangeException e) {}

        clientState = makeClientState(wallet, myKey, ECKey.fromPublicOnly(serverKey.getPubKey()),
                Transaction.MIN_NONDUST_OUTPUT.subtract(Coin.SATOSHI).add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE),
                EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        try {
            clientState.initiate();
            fail();
        } catch (ValueOutOfRangeException e) {}

        // Verify that MIN_NONDUST_OUTPUT + MIN_TX_FEE is accepted
        clientState = makeClientState(wallet, myKey, ECKey.fromPublicOnly(serverKey.getPubKey()),
                Transaction.MIN_NONDUST_OUTPUT.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE), EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        // We'll have to pay REFERENCE_DEFAULT_MIN_TX_FEE twice (multisig+refund), and we'll end up getting back nearly nothing...
        clientState.initiate();
        // Hardcoded tx length because actual length may vary depending on actual signature length
        // The value is close to clientState.getContractInternal().unsafeBitcoinSerialize().length;
        int contractSize = versionSelector == PaymentChannelClient.VersionSelector.VERSION_1 ? 273 : 225;
        Coin expectedFees = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(contractSize).divide(1000).add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE);
        assertEquals(expectedFees, clientState.getRefundTxFees());
        assertEquals(getInitialClientState(), clientState.getState());

        // Now actually use a more useful CENT
        clientState = makeClientState(wallet, myKey, ECKey.fromPublicOnly(serverKey.getPubKey()), CENT, EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        clientState.initiate();
        assertEquals(expectedFees, clientState.getRefundTxFees());
        assertEquals(getInitialClientState(), clientState.getState());

        if (useRefunds()) {
            // Send the refund tx from client to server and get back the signature.
            Transaction refund = new Transaction(PARAMS, clientV1State().getIncompleteRefundTransaction().bitcoinSerialize());
            byte[] refundSig = serverV1State().provideRefundTransaction(refund, myKey.getPubKey());
            assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_CONTRACT, serverState.getState());
            // This verifies that the refund can spend the multi-sig output when run.
            clientV1State().provideRefundSignature(refundSig, null);
        }
        assertEquals(PaymentChannelClientState.State.SAVE_STATE_IN_WALLET, clientState.getState());
        clientState.fakeSave();
        assertEquals(PaymentChannelClientState.State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER, clientState.getState());

        // Get the multisig contract
        Transaction multisigContract = new Transaction(PARAMS, clientState.getContract().bitcoinSerialize());
        assertEquals(PaymentChannelClientState.State.READY, clientState.getState());

        // Provide the server with the multisig contract and simulate successful propagation/acceptance.
        if (!useRefunds()) {
            serverV2State().provideClientKey(clientState.myKey.getPubKey());
        }
        serverState.provideContract(multisigContract);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_ACCEPTANCE, serverState.getState());
        TxFuturePair pair = broadcasts.take();
        pair.future.set(pair.tx);
        assertEquals(PaymentChannelServerState.State.READY, serverState.getState());

        // Both client and server are now in the ready state. Simulate a few micropayments
        Coin totalPayment = Coin.ZERO;

        // We can send as little as we want - its up to the server to get the fees right
        byte[] signature = clientState.incrementPaymentBy(Coin.SATOSHI, null).signature.encodeToBitcoin();
        totalPayment = totalPayment.add(Coin.SATOSHI);
        serverState.incrementPayment(CENT.subtract(totalPayment), signature);

        // We can't refund more than the contract is worth...
        try {
            serverState.incrementPayment(CENT.add(SATOSHI), signature);
            fail();
        } catch (ValueOutOfRangeException e) {}

        // We cannot send just under the total value - our refund would make it unspendable. So the client
        // will correct it for us to be larger than the requested amount, to make the change output zero.
        PaymentChannelClientState.IncrementedPayment payment =
                clientState.incrementPaymentBy(CENT.subtract(Transaction.MIN_NONDUST_OUTPUT), null);
        assertEquals(CENT.subtract(SATOSHI), payment.amount);
        totalPayment = totalPayment.add(payment.amount);

        // The server also won't accept it if we do that.
        try {
            serverState.incrementPayment(Transaction.MIN_NONDUST_OUTPUT.subtract(Coin.SATOSHI), signature);
            fail();
        } catch (ValueOutOfRangeException e) {}

        serverState.incrementPayment(CENT.subtract(totalPayment), payment.signature.encodeToBitcoin());

        // And settle the channel.
        serverState.close();
        assertEquals(PaymentChannelServerState.State.CLOSING, serverState.getState());
        pair = broadcasts.take();  // settle
        pair.future.set(pair.tx);
        assertEquals(PaymentChannelServerState.State.CLOSED, serverState.getState());
        serverState.close();
        assertEquals(PaymentChannelServerState.State.CLOSED, serverState.getState());
    }

    @Test
    public void serverAddsFeeTest() throws Exception {
        // Test that the server properly adds the necessary fee at the end (or just drops the payment if its not worth it)
        Context.propagate(new Context(PARAMS, 100, Coin.ZERO, true));

        Utils.setMockClock(); // Use mock clock
        final long EXPIRE_TIME = Utils.currentTimeMillis()/1000 + 60*60*24;

        serverState = makeServerState(mockBroadcaster, serverWallet, serverKey, EXPIRE_TIME);
        assertEquals(getInitialServerState(), serverState.getState());

        switch (versionSelector) {
            case VERSION_1:
                clientState = new PaymentChannelV1ClientState(wallet, myKey, ECKey.fromPublicOnly(serverKey.getPubKey()), CENT, EXPIRE_TIME) ;
                break;
            case VERSION_2_ALLOW_1:
            case VERSION_2:
                clientState = new PaymentChannelV2ClientState(wallet, myKey, ECKey.fromPublicOnly(serverKey.getPubKey()), CENT, EXPIRE_TIME);
                break;
        }
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        clientState.initiate(null, new PaymentChannelClient.DefaultClientChannelProperties() {
            @Override
            public SendRequest modifyContractSendRequest(SendRequest sendRequest) {
                sendRequest.coinSelector = wallet.getCoinSelector();
                return sendRequest;
            }
        });
        assertEquals(getInitialClientState(), clientState.getState());

        if (useRefunds()) {
            // Send the refund tx from client to server and get back the signature.
            Transaction refund = new Transaction(PARAMS, clientV1State().getIncompleteRefundTransaction().bitcoinSerialize());
            byte[] refundSig = serverV1State().provideRefundTransaction(refund, myKey.getPubKey());
            assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_CONTRACT, serverState.getState());
            // This verifies that the refund can spend the multi-sig output when run.
            clientV1State().provideRefundSignature(refundSig, null);
        }
        assertEquals(PaymentChannelClientState.State.SAVE_STATE_IN_WALLET, clientState.getState());
        clientState.fakeSave();
        assertEquals(PaymentChannelClientState.State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER, clientState.getState());

        // Validate the multisig contract looks right.
        Transaction multisigContract = new Transaction(PARAMS, clientState.getContract().bitcoinSerialize());
        assertEquals(PaymentChannelV1ClientState.State.READY, clientState.getState());
        assertEquals(2, multisigContract.getOutputs().size());   // One multi-sig, one change.
        Script script = multisigContract.getOutput(0).getScriptPubKey();
        if (versionSelector == PaymentChannelClient.VersionSelector.VERSION_1) {
            assertTrue(script.isSentToMultiSig());
        } else {
            assertTrue(script.isPayToScriptHash());
        }
        script = multisigContract.getOutput(1).getScriptPubKey();
        assertTrue(script.isSentToAddress());
        assertTrue(wallet.getPendingTransactions().contains(multisigContract));

        // Provide the server with the multisig contract and simulate successful propagation/acceptance.
        if (!useRefunds()) {
            serverV2State().provideClientKey(clientState.myKey.getPubKey());
        }
        serverState.provideContract(multisigContract);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_ACCEPTANCE, serverState.getState());
        TxFuturePair pair = broadcasts.take();
        pair.future.set(pair.tx);
        assertEquals(PaymentChannelServerState.State.READY, serverState.getState());

        int expectedSize = versionSelector == PaymentChannelClient.VersionSelector.VERSION_1 ? 271 : 355;
        Coin expectedFee = Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(expectedSize).divide(1000);
        // Both client and server are now in the ready state, split the channel in half
        byte[] signature = clientState.incrementPaymentBy(expectedFee.subtract(Coin.SATOSHI), null)
                .signature.encodeToBitcoin();
        Coin totalRefund = CENT.subtract(expectedFee.subtract(SATOSHI));
        serverState.incrementPayment(totalRefund, signature);

        // We need to pay MIN_TX_FEE, but we only have MIN_NONDUST_OUTPUT
        try {
            serverState.close();
            fail();
        } catch (InsufficientMoneyException e) {
            assertTrue(e.getMessage().contains("Insufficient money,  missing "));
        }

        // Now give the server enough coins to pay the fee
        sendMoneyToWallet(serverWallet, AbstractBlockChain.NewBlockType.BEST_CHAIN, COIN, serverKey.toAddress(PARAMS));

        // The contract is still not worth redeeming - its worth less than we pay in fee
        try {
            serverState.close();
            fail();
        } catch (InsufficientMoneyException e) {
            assertTrue(e.getMessage().contains("more in fees"));
        }

        signature = clientState.incrementPaymentBy(SATOSHI.multiply(20), null).signature.encodeToBitcoin();
        totalRefund = totalRefund.subtract(SATOSHI.multiply(20));
        serverState.incrementPayment(totalRefund, signature);

        // And settle the channel.
        serverState.close();
        assertEquals(PaymentChannelServerState.State.CLOSING, serverState.getState());
        pair = broadcasts.take();
        pair.future.set(pair.tx);
        assertEquals(PaymentChannelServerState.State.CLOSED, serverState.getState());
    }

    @Test
    public void doubleSpendContractTest() throws Exception {
        // Tests that if the client double-spends the multisig contract after it is sent, no more payments are accepted

        // Start with a copy of basic()....
        Utils.setMockClock(); // Use mock clock
        final long EXPIRE_TIME = Utils.currentTimeSeconds() + 60*60*24;

        serverState = makeServerState(mockBroadcaster, serverWallet, serverKey, EXPIRE_TIME);
        assertEquals(getInitialServerState(), serverState.getState());

        clientState = makeClientState(wallet, myKey, ECKey.fromPublicOnly(serverKey.getPubKey()), HALF_COIN, EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        clientState.initiate();
        assertEquals(getInitialClientState(), clientState.getState());

        Transaction refund;
        if (useRefunds()) {
            refund = new Transaction(PARAMS, clientV1State().getIncompleteRefundTransaction().bitcoinSerialize());
            // Send the refund tx from client to server and get back the signature.
            byte[] refundSig = serverV1State().provideRefundTransaction(refund, myKey.getPubKey());
            assertEquals(PaymentChannelV1ServerState.State.WAITING_FOR_MULTISIG_CONTRACT, serverState.getState());
            // This verifies that the refund can spend the multi-sig output when run.
            clientV1State().provideRefundSignature(refundSig, null);
        } else {
            refund = clientV2State().getRefundTransaction();
        }
        assertEquals(PaymentChannelClientState.State.SAVE_STATE_IN_WALLET, clientState.getState());
        clientState.fakeSave();
        assertEquals(PaymentChannelClientState.State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER, clientState.getState());

        // Validate the multisig contract looks right.
        Transaction multisigContract = new Transaction(PARAMS, clientState.getContract().bitcoinSerialize());
        assertEquals(PaymentChannelClientState.State.READY, clientState.getState());
        assertEquals(2, multisigContract.getOutputs().size());   // One multi-sig, one change.
        Script script = multisigContract.getOutput(0).getScriptPubKey();
        if (versionSelector == PaymentChannelClient.VersionSelector.VERSION_1) {
            assertTrue(script.isSentToMultiSig());
        } else {
            assertTrue(script.isPayToScriptHash());
        }
        script = multisigContract.getOutput(1).getScriptPubKey();
        assertTrue(script.isSentToAddress());
        assertTrue(wallet.getPendingTransactions().contains(multisigContract));

        // Provide the server with the multisig contract and simulate successful propagation/acceptance.
        if (!useRefunds()) {
            serverV2State().provideClientKey(clientState.myKey.getPubKey());
        }
        serverState.provideContract(multisigContract);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_ACCEPTANCE, serverState.getState());
        final TxFuturePair pair = broadcasts.take();
        pair.future.set(pair.tx);
        assertEquals(PaymentChannelServerState.State.READY, serverState.getState());

        // Make sure the refund transaction is not in the wallet and multisig contract's output is not connected to it
        assertEquals(2, wallet.getTransactions(false).size());
        Iterator<Transaction> walletTransactionIterator = wallet.getTransactions(false).iterator();
        Transaction clientWalletMultisigContract = walletTransactionIterator.next();
        assertFalse(clientWalletMultisigContract.getHash().equals(clientState.getRefundTransaction().getHash()));
        if (!clientWalletMultisigContract.getHash().equals(multisigContract.getHash())) {
            clientWalletMultisigContract = walletTransactionIterator.next();
            assertFalse(clientWalletMultisigContract.getHash().equals(clientState.getRefundTransaction().getHash()));
        } else
            assertFalse(walletTransactionIterator.next().getHash().equals(clientState.getRefundTransaction().getHash()));
        assertEquals(multisigContract.getHash(), clientWalletMultisigContract.getHash());
        assertFalse(clientWalletMultisigContract.getInput(0).getConnectedOutput().getSpentBy().getParentTransaction().getHash().equals(refund.getHash()));

        // Both client and server are now in the ready state. Simulate a few micropayments of 0.005 bitcoins.
        Coin size = HALF_COIN.divide(100);
        Coin totalPayment = Coin.ZERO;
        for (int i = 0; i < 5; i++) {
            byte[] signature = clientState.incrementPaymentBy(size, null).signature.encodeToBitcoin();
            totalPayment = totalPayment.add(size);
            serverState.incrementPayment(HALF_COIN.subtract(totalPayment), signature);
        }

        // Now create a double-spend and send it to the server
        Transaction doubleSpendContract = new Transaction(PARAMS);
        doubleSpendContract.addInput(new TransactionInput(PARAMS, doubleSpendContract, new byte[0],
                multisigContract.getInput(0).getOutpoint()));
        doubleSpendContract.addOutput(HALF_COIN, myKey);
        doubleSpendContract = new Transaction(PARAMS, doubleSpendContract.bitcoinSerialize());

        StoredBlock block = new StoredBlock(PARAMS.getGenesisBlock().createNextBlock(myKey.toAddress(PARAMS)), BigInteger.TEN, 1);
        serverWallet.receiveFromBlock(doubleSpendContract, block, AbstractBlockChain.NewBlockType.BEST_CHAIN, 0);

        // Now if we try to spend again the server will reject it since it saw a double-spend
        try {
            byte[] signature = clientState.incrementPaymentBy(size, null).signature.encodeToBitcoin();
            totalPayment = totalPayment.add(size);
            serverState.incrementPayment(HALF_COIN.subtract(totalPayment), signature);
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("double-spent"));
        }
    }
}
