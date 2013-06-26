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

package com.google.bitcoin.protocols.channels;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Iterator;
import java.util.concurrent.ExecutionException;

import com.google.bitcoin.core.*;
import com.google.bitcoin.script.Script;
import com.google.bitcoin.script.ScriptBuilder;
import com.google.common.collect.Lists;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.SettableFuture;
import org.easymock.Capture;
import org.easymock.IMocksControl;
import org.junit.Before;
import org.junit.Test;

import static com.google.bitcoin.core.TestUtils.createFakeTx;
import static com.google.bitcoin.core.TestUtils.makeSolvedTestBlock;
import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

public class PaymentChannelStateTest extends TestWithWallet {
    private ECKey serverKey;
    private BigInteger halfCoin;
    private Wallet serverWallet;
    private PaymentChannelServerState serverState;
    private PaymentChannelClientState clientState;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        wallet.addExtension(new StoredPaymentChannelClientStates(new TransactionBroadcaster() {
            @Override
            public ListenableFuture<Transaction> broadcastTransaction(Transaction tx) {
                fail();
                return null;
            }
        }, wallet));
        sendMoneyToWallet(Utils.COIN, AbstractBlockChain.NewBlockType.BEST_CHAIN);
        chain = new BlockChain(params, wallet, blockStore); // Recreate chain as sendMoneyToWallet will confuse it
        serverKey = new ECKey();
        serverWallet = new Wallet(params);
        serverWallet.addKey(serverKey);
        chain.addWallet(serverWallet);
        halfCoin = Utils.toNanoCoins(0, 50);
    }

    @Test
    public void stateErrors() throws Exception {
        PaymentChannelClientState channelState = new PaymentChannelClientState(wallet, myKey, serverKey,
                Utils.COIN.multiply(BigInteger.TEN), 20);
        assertEquals(PaymentChannelClientState.State.NEW, channelState.getState());
        try {
            channelState.getMultisigContract();
            fail();
        } catch (IllegalStateException e) {
            // Expected.
        }
        try {
            channelState.initiate();
            fail();
        } catch (ValueOutOfRangeException e) {
            assertTrue(e.getMessage().contains("afford"));
        }
    }

    @Test
    public void basic() throws Exception {
        // Check it all works when things are normal (no attacks, no problems).

        // Set up a mock peergroup.
        IMocksControl control = createStrictControl();
        PeerGroup mockPeerGroup = control.createMock(PeerGroup.class);
        // We'll broadcast two txns: multisig contract and close transaction.
        SettableFuture<Transaction> multiSigFuture = SettableFuture.create();
        SettableFuture<Transaction> closeFuture = SettableFuture.create();
        Capture<Transaction> broadcastMultiSig = new Capture<Transaction>();
        Capture<Transaction> broadcastClose = new Capture<Transaction>();
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastMultiSig))).andReturn(multiSigFuture);
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastClose))).andReturn(closeFuture);
        control.replay();

        Utils.rollMockClock(0); // Use mock clock
        final long EXPIRE_TIME = Utils.now().getTime()/1000 + 60*60*24;

        serverState = new PaymentChannelServerState(mockPeerGroup, serverWallet, serverKey, EXPIRE_TIME);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_REFUND_TRANSACTION, serverState.getState());

        clientState = new PaymentChannelClientState(wallet, myKey, new ECKey(null, serverKey.getPubKey()), halfCoin, EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        clientState.initiate();
        assertEquals(PaymentChannelClientState.State.INITIATED, clientState.getState());

        // Send the refund tx from client to server and get back the signature.
        Transaction refund = new Transaction(params, clientState.getIncompleteRefundTransaction().bitcoinSerialize());
        byte[] refundSig = serverState.provideRefundTransaction(refund, myKey.getPubKey());
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_CONTRACT, serverState.getState());
        // This verifies that the refund can spend the multi-sig output when run.
        clientState.provideRefundSignature(refundSig);
        assertEquals(PaymentChannelClientState.State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER, clientState.getState());

        // Validate the multisig contract looks right.
        Transaction multisigContract = new Transaction(params, clientState.getMultisigContract().bitcoinSerialize());
        assertEquals(PaymentChannelClientState.State.READY, clientState.getState());
        assertEquals(2, multisigContract.getOutputs().size());   // One multi-sig, one change.
        Script script = multisigContract.getOutput(0).getScriptPubKey();
        assertTrue(script.isSentToMultiSig());
        script = multisigContract.getOutput(1).getScriptPubKey();
        assertTrue(script.isSentToAddress());
        assertTrue(wallet.getPendingTransactions().contains(multisigContract));

        // Provide the server with the multisig contract and simulate successful propagation/acceptance.
        serverState.provideMultiSigContract(multisigContract);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_ACCEPTANCE, serverState.getState());
        multiSigFuture.set(broadcastMultiSig.getValue());
        assertEquals(PaymentChannelServerState.State.READY, serverState.getState());

        // Make sure the refund transaction is not in the wallet and multisig contract's output is not connected to it
        assertEquals(2, wallet.getTransactions(false).size());
        Iterator<Transaction> walletTransactionIterator = wallet.getTransactions(false).iterator();
        Transaction clientWalletMultisigContract = walletTransactionIterator.next();
        assertFalse(clientWalletMultisigContract.getHash().equals(clientState.getCompletedRefundTransaction().getHash()));
        if (!clientWalletMultisigContract.getHash().equals(multisigContract.getHash())) {
            clientWalletMultisigContract = walletTransactionIterator.next();
            assertFalse(clientWalletMultisigContract.getHash().equals(clientState.getCompletedRefundTransaction().getHash()));
        } else
            assertFalse(walletTransactionIterator.next().getHash().equals(clientState.getCompletedRefundTransaction().getHash()));
        assertEquals(multisigContract.getHash(), clientWalletMultisigContract.getHash());
        assertFalse(clientWalletMultisigContract.getInput(0).getConnectedOutput().getSpentBy().getParentTransaction().getHash().equals(refund.getHash()));

        // Both client and server are now in the ready state. Simulate a few micropayments of 0.005 bitcoins.
        BigInteger size = halfCoin.divide(BigInteger.TEN).divide(BigInteger.TEN);
        BigInteger totalPayment = BigInteger.ZERO;
        for (int i = 0; i < 5; i++) {
            byte[] signature = clientState.incrementPaymentBy(size);
            totalPayment = totalPayment.add(size);
            serverState.incrementPayment(halfCoin.subtract(totalPayment), signature);
        }

        // And close the channel.
        serverState.close();
        assertEquals(PaymentChannelServerState.State.CLOSING, serverState.getState());
        Transaction closeTx = broadcastClose.getValue();
        closeFuture.set(closeTx);
        assertEquals(PaymentChannelServerState.State.CLOSED, serverState.getState());
        control.verify();

        // Create a block with multisig contract and payment transaction in it and give it to both wallets
        chain.add(makeSolvedTestBlock(blockStore.getChainHead().getHeader(), multisigContract,
                                      new Transaction(params, closeTx.bitcoinSerialize())));

        assertEquals(size.multiply(BigInteger.valueOf(5)), serverWallet.getBalance(new Wallet.DefaultCoinSelector() {
            @Override
            protected boolean shouldSelect(Transaction tx) {
                if (tx.getConfidence().getConfidenceType() == TransactionConfidence.ConfidenceType.BUILDING)
                    return true;
                return false;
            }
        }));
        assertEquals(0, serverWallet.getPendingTransactions().size());

        assertEquals(Utils.COIN.subtract(size.multiply(BigInteger.valueOf(5))), wallet.getBalance(new Wallet.DefaultCoinSelector() {
            @Override
            protected boolean shouldSelect(Transaction tx) {
                if (tx.getConfidence().getConfidenceType() == TransactionConfidence.ConfidenceType.BUILDING)
                    return true;
                return false;
            }
        }));
        assertEquals(0, wallet.getPendingTransactions().size());
        assertEquals(3, wallet.getTransactions(false).size());

        walletTransactionIterator = wallet.getTransactions(false).iterator();
        Transaction clientWalletCloseTransaction = walletTransactionIterator.next();
        if (!clientWalletCloseTransaction.getHash().equals(closeTx.getHash()))
            clientWalletCloseTransaction = walletTransactionIterator.next();
        if (!clientWalletCloseTransaction.getHash().equals(closeTx.getHash()))
            clientWalletCloseTransaction = walletTransactionIterator.next();
        assertEquals(closeTx.getHash(), clientWalletCloseTransaction.getHash());
        assertTrue(clientWalletCloseTransaction.getInput(0).getConnectedOutput() != null);

        control.verify();
    }

    @Test
    public void setupDoS() throws Exception {
        // Check that if the other side stops after we have provided a signed multisig contract, that after a timeout
        // we can broadcast the refund and get our balance back.

        // Spend the client wallet's one coin
        Transaction spendCoinTx = wallet.sendCoinsOffline(Wallet.SendRequest.to(new ECKey().toAddress(params), Utils.COIN));
        assertEquals(wallet.getBalance(), BigInteger.ZERO);
        chain.add(makeSolvedTestBlock(blockStore.getChainHead().getHeader(), spendCoinTx, createFakeTx(params, Utils.CENT, myAddress)));
        assertEquals(wallet.getBalance(), Utils.CENT);

        // Set up a mock peergroup.
        IMocksControl control = createStrictControl();
        final PeerGroup mockPeerGroup = control.createMock(PeerGroup.class);
        // We'll broadcast three txns: multisig contract twice (both server and client) and refund transaction.
        SettableFuture<Transaction> serverMultiSigFuture = SettableFuture.create();
        SettableFuture<Transaction> paymentFuture = SettableFuture.create();
        SettableFuture<Transaction> clientMultiSigFuture = SettableFuture.create();
        SettableFuture<Transaction> refundFuture = SettableFuture.create();
        Capture<Transaction> serverBroadcastMultiSig = new Capture<Transaction>();
        Capture<Transaction> broadcastPayment = new Capture<Transaction>();
        Capture<Transaction> clientBroadcastMultiSig = new Capture<Transaction>();
        Capture<Transaction> broadcastRefund = new Capture<Transaction>();
        expect(mockPeerGroup.broadcastTransaction(capture(serverBroadcastMultiSig))).andReturn(serverMultiSigFuture);
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastPayment))).andReturn(paymentFuture);
        expect(mockPeerGroup.broadcastTransaction(capture(clientBroadcastMultiSig))).andReturn(clientMultiSigFuture);
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastRefund))).andReturn(refundFuture);
        control.replay();

        // Set the wallet's stored states to use our real test PeerGroup
        StoredPaymentChannelClientStates stateStorage = new StoredPaymentChannelClientStates(new TransactionBroadcaster() {
            @Override
            public ListenableFuture<Transaction> broadcastTransaction(Transaction tx) {
                return mockPeerGroup.broadcastTransaction(tx);
            }
        }, wallet);
        wallet.addOrUpdateExtension(stateStorage);

        Utils.rollMockClock(0); // Use mock clock
        final long EXPIRE_TIME = Utils.now().getTime()/1000 + 60*60*24;

        serverState = new PaymentChannelServerState(mockPeerGroup, serverWallet, serverKey, EXPIRE_TIME);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_REFUND_TRANSACTION, serverState.getState());

        clientState = new PaymentChannelClientState(wallet, myKey, new ECKey(null, serverKey.getPubKey()),
                                                    Utils.CENT.divide(BigInteger.valueOf(2)), EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        assertEquals(Utils.CENT.divide(BigInteger.valueOf(2)), clientState.getTotalValue());
        clientState.initiate();
        // We will have to pay min_tx_fee twice - both the multisig contract and the refund tx
        assertEquals(clientState.getRefundTxFees(), Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(BigInteger.valueOf(2)));
        assertEquals(PaymentChannelClientState.State.INITIATED, clientState.getState());

        // Send the refund tx from client to server and get back the signature.
        Transaction refund = new Transaction(params, clientState.getIncompleteRefundTransaction().bitcoinSerialize());
        byte[] refundSig = serverState.provideRefundTransaction(refund, myKey.getPubKey());
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_CONTRACT, serverState.getState());
        // This verifies that the refund can spend the multi-sig output when run.
        clientState.provideRefundSignature(refundSig);
        assertEquals(PaymentChannelClientState.State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER, clientState.getState());

        // Validate the multisig contract looks right.
        Transaction multisigContract = new Transaction(params, clientState.getMultisigContract().bitcoinSerialize());
        assertEquals(PaymentChannelClientState.State.READY, clientState.getState());
        assertEquals(2, multisigContract.getOutputs().size());   // One multi-sig, one change.
        Script script = multisigContract.getOutput(0).getScriptPubKey();
        assertTrue(script.isSentToMultiSig());
        script = multisigContract.getOutput(1).getScriptPubKey();
        assertTrue(script.isSentToAddress());
        assertTrue(wallet.getPendingTransactions().contains(multisigContract));

        // Provide the server with the multisig contract and simulate successful propagation/acceptance.
        serverState.provideMultiSigContract(multisigContract);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_ACCEPTANCE, serverState.getState());
        serverMultiSigFuture.set(serverBroadcastMultiSig.getValue());
        assertEquals(PaymentChannelServerState.State.READY, serverState.getState());

        // Pay a tiny bit
        serverState.incrementPayment(Utils.CENT.divide(BigInteger.valueOf(2)).subtract(Utils.CENT.divide(BigInteger.TEN)),
                clientState.incrementPaymentBy(Utils.CENT.divide(BigInteger.TEN)));

        // Advance time until our we get close enough to lock time that server should rebroadcast
        Utils.rollMockClock(60*60*22);
        // ... and store server to get it to broadcast payment transaction
        serverState.storeChannelInWallet(null);
        while (!broadcastPayment.hasCaptured())
            Thread.sleep(100);
        Exception paymentException = new RuntimeException("I'm sorry, but the network really just doesn't like you");
        paymentFuture.setException(paymentException);
        try {
            serverState.close().get();
        } catch (ExecutionException e) {
            assertTrue(e.getCause() == paymentException);
        }
        assertEquals(PaymentChannelServerState.State.ERROR, serverState.getState());

        // Now advance until client should rebroadcast
        Utils.rollMockClock(60*60*2 + 60*5);

        // Now store the client state in a stored state object which handles the rebroadcasting
        clientState.storeChannelInWallet(Sha256Hash.create(new byte[] {}));
        while (!broadcastRefund.hasCaptured())
            Thread.sleep(100);

        Transaction clientBroadcastedMultiSig = clientBroadcastMultiSig.getValue();
        assertTrue(clientBroadcastedMultiSig.getHash().equals(multisigContract.getHash()));
        for (TransactionInput input : clientBroadcastedMultiSig.getInputs())
            input.verify();
        clientMultiSigFuture.set(clientBroadcastedMultiSig);

        Transaction clientBroadcastedRefund = broadcastRefund.getValue();
        assertTrue(clientBroadcastedRefund.getHash().equals(clientState.getCompletedRefundTransaction().getHash()));
        for (TransactionInput input : clientBroadcastedRefund.getInputs()) {
            // If the multisig output is connected, the wallet will fail to deserialize
            if (input.getOutpoint().getHash().equals(clientBroadcastedMultiSig.getHash()))
                assertNull(input.getConnectedOutput().getSpentBy());
            input.verify(clientBroadcastedMultiSig.getOutput(0));
        }
        refundFuture.set(clientBroadcastedRefund);

        // Create a block with multisig contract and refund transaction in it and give it to both wallets,
        // making getBalance() include the transactions
        chain.add(makeSolvedTestBlock(blockStore.getChainHead().getHeader(), multisigContract,clientBroadcastedRefund));

        // Make sure we actually had to pay what initialize() told us we would
        assertEquals(wallet.getBalance(), Utils.CENT.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(BigInteger.valueOf(2))));

        try {
            // After its expired, we cant still increment payment
            clientState.incrementPaymentBy(Utils.CENT);
            fail();
        } catch (IllegalStateException e) { }

        control.verify();
    }

    @Test
    public void checkBadData() throws Exception {
        // Check that if signatures/transactions/etc are corrupted, the protocol rejects them correctly.

        // Set up a mock peergroup.
        IMocksControl control = createStrictControl();
        PeerGroup mockPeerGroup = control.createMock(PeerGroup.class);

        // We'll broadcast only one tx: multisig contract
        SettableFuture<Transaction> multiSigFuture = SettableFuture.create();
        Capture<Transaction> broadcastMultiSig = new Capture<Transaction>();
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastMultiSig))).andReturn(multiSigFuture);
        control.replay();

        Utils.rollMockClock(0); // Use mock clock
        final long EXPIRE_TIME = Utils.now().getTime()/1000 + 60*60*24;

        serverState = new PaymentChannelServerState(mockPeerGroup, serverWallet, serverKey, EXPIRE_TIME);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_REFUND_TRANSACTION, serverState.getState());

        try {
            clientState = new PaymentChannelClientState(wallet, myKey, new ECKey(null,
                    Arrays.copyOf(serverKey.getPubKey(), serverKey.getPubKey().length + 1)), halfCoin, EXPIRE_TIME);
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("not canonical"));
        }

        clientState = new PaymentChannelClientState(wallet, myKey, new ECKey(null, serverKey.getPubKey()), halfCoin, EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        clientState.initiate();
        assertEquals(PaymentChannelClientState.State.INITIATED, clientState.getState());

        // Test refund transaction with any number of issues
        byte[] refundTxBytes = clientState.getIncompleteRefundTransaction().bitcoinSerialize();
        Transaction refund = new Transaction(params, refundTxBytes);
        refund.addOutput(BigInteger.ZERO, new ECKey().toAddress(params));
        try {
            serverState.provideRefundTransaction(refund, myKey.getPubKey());
            fail();
        } catch (VerificationException e) {}

        refund = new Transaction(params, refundTxBytes);
        refund.addInput(new TransactionInput(params, refund, new byte[] {}, new TransactionOutPoint(params, 42, refund.getHash())));
        try {
            serverState.provideRefundTransaction(refund, myKey.getPubKey());
            fail();
        } catch (VerificationException e) {}

        refund = new Transaction(params, refundTxBytes);
        refund.setLockTime(0);
        try {
            serverState.provideRefundTransaction(refund, myKey.getPubKey());
            fail();
        } catch (VerificationException e) {}

        refund = new Transaction(params, refundTxBytes);
        refund.getInput(0).setSequenceNumber(TransactionInput.NO_SEQUENCE);
        try {
            serverState.provideRefundTransaction(refund, myKey.getPubKey());
            fail();
        } catch (VerificationException e) {}

        refund = new Transaction(params, refundTxBytes);
        byte[] refundSig = serverState.provideRefundTransaction(refund, myKey.getPubKey());
        try { serverState.provideRefundTransaction(refund, myKey.getPubKey()); fail(); } catch (IllegalStateException e) {}
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_CONTRACT, serverState.getState());

        byte[] refundSigCopy = Arrays.copyOf(refundSig, refundSig.length);
        refundSigCopy[refundSigCopy.length-1] = (byte) (Transaction.SigHash.NONE.ordinal() + 1);
        try {
            clientState.provideRefundSignature(refundSigCopy);
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("SIGHASH_NONE"));
        }

        refundSigCopy = Arrays.copyOf(refundSig, refundSig.length);
        refundSigCopy[3] ^= 0x42; // Make the signature fail standard checks
        try {
            clientState.provideRefundSignature(refundSigCopy);
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("not canonical"));
        }

        refundSigCopy = Arrays.copyOf(refundSig, refundSig.length);
        refundSigCopy[10] ^= 0x42; // Flip some random bits in the signature (to make it invalid, not just nonstandard)
        try {
            clientState.provideRefundSignature(refundSigCopy);
            fail();
        } catch (VerificationException e) {
            assertFalse(e.getMessage().contains("not canonical"));
        }

        refundSigCopy = Arrays.copyOf(refundSig, refundSig.length);
        try { clientState.getCompletedRefundTransaction(); fail(); } catch (IllegalStateException e) {}
        clientState.provideRefundSignature(refundSigCopy);
        try { clientState.provideRefundSignature(refundSigCopy); fail(); } catch (IllegalStateException e) {}
        assertEquals(PaymentChannelClientState.State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER, clientState.getState());

        try { clientState.incrementPaymentBy(BigInteger.ONE); fail(); } catch (IllegalStateException e) {}

        byte[] multisigContractSerialized = clientState.getMultisigContract().bitcoinSerialize();

        Transaction multisigContract = new Transaction(params, multisigContractSerialized);
        multisigContract.clearOutputs();
        multisigContract.addOutput(halfCoin, ScriptBuilder.createMultiSigOutputScript(2, Lists.newArrayList(serverKey, myKey)));
        try {
            serverState.provideMultiSigContract(multisigContract);
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("client and server in that order"));
        }

        multisigContract = new Transaction(params, multisigContractSerialized);
        multisigContract.clearOutputs();
        multisigContract.addOutput(BigInteger.ZERO, ScriptBuilder.createMultiSigOutputScript(2, Lists.newArrayList(myKey, serverKey)));
        try {
            serverState.provideMultiSigContract(multisigContract);
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("zero value"));
        }

        multisigContract = new Transaction(params, multisigContractSerialized);
        multisigContract.clearOutputs();
        multisigContract.addOutput(new TransactionOutput(params, multisigContract, halfCoin, new byte[] {0x01}));
        try {
            serverState.provideMultiSigContract(multisigContract);
            fail();
        } catch (VerificationException e) {}

        multisigContract = new Transaction(params, multisigContractSerialized);
        ListenableFuture<PaymentChannelServerState> multisigStateFuture = serverState.provideMultiSigContract(multisigContract);
        try { serverState.provideMultiSigContract(multisigContract); fail(); } catch (IllegalStateException e) {}
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_ACCEPTANCE, serverState.getState());
        assertFalse(multisigStateFuture.isDone());
        multiSigFuture.set(broadcastMultiSig.getValue());
        assertEquals(multisigStateFuture.get(), serverState);
        assertEquals(PaymentChannelServerState.State.READY, serverState.getState());

        // Both client and server are now in the ready state. Simulate a few micropayments of 0.005 bitcoins.
        BigInteger size = halfCoin.divide(BigInteger.TEN).divide(BigInteger.TEN);
        BigInteger totalPayment = BigInteger.ZERO;
        try {
            clientState.incrementPaymentBy(Utils.COIN);
            fail();
        } catch (ValueOutOfRangeException e) {}

        byte[] signature = clientState.incrementPaymentBy(size);
        totalPayment = totalPayment.add(size);

        byte[] signatureCopy = Arrays.copyOf(signature, signature.length);
        signatureCopy[signatureCopy.length - 1] = (byte) ((Transaction.SigHash.NONE.ordinal() + 1) | 0x80);
        try {
            serverState.incrementPayment(halfCoin.subtract(totalPayment), signatureCopy);
            fail();
        } catch (VerificationException e) {}

        signatureCopy = Arrays.copyOf(signature, signature.length);
        signatureCopy[2]  ^= 0x42; // Make the signature fail standard checks
        try {
            serverState.incrementPayment(halfCoin.subtract(totalPayment), signatureCopy);
            fail();
        } catch (VerificationException e) {
            assertTrue(e.getMessage().contains("not canonical"));
        }

        signatureCopy = Arrays.copyOf(signature, signature.length);
        signatureCopy[10]  ^= 0x42; // Flip some random bits in the signature (to make it invalid, not just nonstandard)
        try {
            serverState.incrementPayment(halfCoin.subtract(totalPayment), signatureCopy);
            fail();
        } catch (VerificationException e) {
            assertFalse(e.getMessage().contains("not canonical"));
        }

        serverState.incrementPayment(halfCoin.subtract(totalPayment), signature);

        // Pay the rest (signed with SIGHASH_NONE|SIGHASH_ANYONECANPAY)
        byte[] signature2 = clientState.incrementPaymentBy(halfCoin.subtract(totalPayment));
        totalPayment = totalPayment.add(halfCoin.subtract(totalPayment));
        assertEquals(totalPayment, halfCoin);

        signatureCopy = Arrays.copyOf(signature, signature.length);
        signatureCopy[signatureCopy.length - 1] = (byte) ((Transaction.SigHash.SINGLE.ordinal() + 1) | 0x80);
        try {
            serverState.incrementPayment(halfCoin.subtract(totalPayment), signatureCopy);
            fail();
        } catch (VerificationException e) {}

        serverState.incrementPayment(halfCoin.subtract(totalPayment), signature2);

        serverState.incrementPayment(halfCoin.subtract(totalPayment.subtract(size)), signature);
        assertEquals(serverState.getBestValueToMe(), totalPayment);

        try {
            clientState.incrementPaymentBy(BigInteger.ONE.negate());
            fail();
        } catch (ValueOutOfRangeException e) {}

        try {
            clientState.incrementPaymentBy(halfCoin.subtract(size).add(BigInteger.ONE));
            fail();
        } catch (ValueOutOfRangeException e) {}

        control.verify();
    }

    @Test
    public void feesTest() throws Exception {
        // Test that transactions are getting the necessary fees

        // Spend the client wallet's one coin
        wallet.sendCoinsOffline(Wallet.SendRequest.to(new ECKey().toAddress(params), Utils.COIN));
        assertEquals(wallet.getBalance(), BigInteger.ZERO);

        chain.add(makeSolvedTestBlock(blockStore.getChainHead().getHeader(), createFakeTx(params, Utils.CENT, myAddress)));
        assertEquals(wallet.getBalance(), Utils.CENT);

        // Set up a mock peergroup.
        IMocksControl control = createStrictControl();
        PeerGroup mockPeerGroup = control.createMock(PeerGroup.class);
        // We'll broadcast two txns: multisig contract and close transaction.
        SettableFuture<Transaction> multiSigFuture = SettableFuture.create();
        SettableFuture<Transaction> closeFuture = SettableFuture.create();
        Capture<Transaction> broadcastMultiSig = new Capture<Transaction>();
        Capture<Transaction> broadcastClose = new Capture<Transaction>();
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastMultiSig))).andReturn(multiSigFuture);
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastClose))).andReturn(closeFuture);
        control.replay();

        Utils.rollMockClock(0); // Use mock clock
        final long EXPIRE_TIME = Utils.now().getTime()/1000 + 60*60*24;

        serverState = new PaymentChannelServerState(mockPeerGroup, serverWallet, serverKey, EXPIRE_TIME);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_REFUND_TRANSACTION, serverState.getState());

        // Clearly ONE is far too small to be useful
        clientState = new PaymentChannelClientState(wallet, myKey, new ECKey(null, serverKey.getPubKey()), BigInteger.ONE, EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        try {
            clientState.initiate();
            fail();
        } catch (ValueOutOfRangeException e) {}

        clientState = new PaymentChannelClientState(wallet, myKey, new ECKey(null, serverKey.getPubKey()),
                                                    Transaction.MIN_NONDUST_OUTPUT.subtract(BigInteger.ONE).add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE),
                EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        try {
            clientState.initiate();
            fail();
        } catch (ValueOutOfRangeException e) {}

        // Verify that MIN_NONDUST_OUTPUT + MIN_TX_FEE is accepted
        clientState = new PaymentChannelClientState(wallet, myKey, new ECKey(null, serverKey.getPubKey()),
                Transaction.MIN_NONDUST_OUTPUT.add(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE), EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        // We'll have to pay REFERENCE_DEFAULT_MIN_TX_FEE twice (multisig+refund), and we'll end up getting back nearly nothing...
        clientState.initiate();
        assertEquals(clientState.getRefundTxFees(), Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.multiply(BigInteger.valueOf(2)));
        assertEquals(PaymentChannelClientState.State.INITIATED, clientState.getState());

        // Now actually use a more useful CENT
        clientState = new PaymentChannelClientState(wallet, myKey, new ECKey(null, serverKey.getPubKey()), Utils.CENT, EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        clientState.initiate();
        assertEquals(clientState.getRefundTxFees(), BigInteger.ZERO);
        assertEquals(PaymentChannelClientState.State.INITIATED, clientState.getState());

        // Send the refund tx from client to server and get back the signature.
        Transaction refund = new Transaction(params, clientState.getIncompleteRefundTransaction().bitcoinSerialize());
        byte[] refundSig = serverState.provideRefundTransaction(refund, myKey.getPubKey());
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_CONTRACT, serverState.getState());
        // This verifies that the refund can spend the multi-sig output when run.
        clientState.provideRefundSignature(refundSig);
        assertEquals(PaymentChannelClientState.State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER, clientState.getState());

        // Get the multisig contract
        Transaction multisigContract = new Transaction(params, clientState.getMultisigContract().bitcoinSerialize());
        assertEquals(PaymentChannelClientState.State.READY, clientState.getState());

        // Provide the server with the multisig contract and simulate successful propagation/acceptance.
        serverState.provideMultiSigContract(multisigContract);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_ACCEPTANCE, serverState.getState());
        multiSigFuture.set(broadcastMultiSig.getValue());
        assertEquals(PaymentChannelServerState.State.READY, serverState.getState());

        // Both client and server are now in the ready state. Simulate a few micropayments
        BigInteger totalPayment = BigInteger.ZERO;

        // We can send as little as we want - its up to the server to get the fees right
        byte[] signature = clientState.incrementPaymentBy(BigInteger.ONE);
        totalPayment = totalPayment.add(BigInteger.ONE);
        serverState.incrementPayment(Utils.CENT.subtract(totalPayment), signature);

        // We can't refund more than the contract is worth...
        try {
            serverState.incrementPayment(Utils.CENT.add(BigInteger.ONE), signature);
            fail();
        } catch (ValueOutOfRangeException e) {}

        // We cannot, however, send just under the total value - our refund would make it unspendable
        try {
            clientState.incrementPaymentBy(Utils.CENT.subtract(Transaction.MIN_NONDUST_OUTPUT));
            fail();
        } catch (ValueOutOfRangeException e) {}
        // The server also won't accept it if we do that
        try {
            serverState.incrementPayment(Transaction.MIN_NONDUST_OUTPUT.subtract(BigInteger.ONE), signature);
            fail();
        } catch (ValueOutOfRangeException e) {}

        signature = clientState.incrementPaymentBy(Utils.CENT.subtract(BigInteger.ONE));
        totalPayment = totalPayment.add(Utils.CENT.subtract(BigInteger.ONE));
        assertEquals(totalPayment, Utils.CENT);
        serverState.incrementPayment(Utils.CENT.subtract(totalPayment), signature);

        // And close the channel.
        serverState.close();
        assertEquals(PaymentChannelServerState.State.CLOSING, serverState.getState());
        Transaction closeTx = broadcastClose.getValue();
        closeFuture.set(closeTx);
        assertEquals(PaymentChannelServerState.State.CLOSED, serverState.getState());
        serverState.close();
        assertEquals(PaymentChannelServerState.State.CLOSED, serverState.getState());
        control.verify();
    }

    @Test
    public void serverAddsFeeTest() throws Exception {
        // Test that the server properly adds the necessary fee at the end (or just drops the payment if its not worth it)

        // Set up a mock peergroup.
        IMocksControl control = createStrictControl();
        PeerGroup mockPeerGroup = control.createMock(PeerGroup.class);
        // We'll broadcast two txns: multisig contract and close transaction.
        SettableFuture<Transaction> multiSigFuture = SettableFuture.create();
        SettableFuture<Transaction> closeFuture = SettableFuture.create();
        Capture<Transaction> broadcastMultiSig = new Capture<Transaction>();
        Capture<Transaction> broadcastClose = new Capture<Transaction>();
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastMultiSig))).andReturn(multiSigFuture);
        expect(mockPeerGroup.broadcastTransaction(capture(broadcastClose))).andReturn(closeFuture);
        control.replay();

        Utils.rollMockClock(0); // Use mock clock
        final long EXPIRE_TIME = Utils.now().getTime()/1000 + 60*60*24;

        serverState = new PaymentChannelServerState(mockPeerGroup, serverWallet, serverKey, EXPIRE_TIME);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_REFUND_TRANSACTION, serverState.getState());

        clientState = new PaymentChannelClientState(wallet, myKey, new ECKey(null, serverKey.getPubKey()), Utils.CENT, EXPIRE_TIME);
        assertEquals(PaymentChannelClientState.State.NEW, clientState.getState());
        clientState.initiate();
        assertEquals(PaymentChannelClientState.State.INITIATED, clientState.getState());

        // Send the refund tx from client to server and get back the signature.
        Transaction refund = new Transaction(params, clientState.getIncompleteRefundTransaction().bitcoinSerialize());
        byte[] refundSig = serverState.provideRefundTransaction(refund, myKey.getPubKey());
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_CONTRACT, serverState.getState());
        // This verifies that the refund can spend the multi-sig output when run.
        clientState.provideRefundSignature(refundSig);
        assertEquals(PaymentChannelClientState.State.PROVIDE_MULTISIG_CONTRACT_TO_SERVER, clientState.getState());

        // Validate the multisig contract looks right.
        Transaction multisigContract = new Transaction(params, clientState.getMultisigContract().bitcoinSerialize());
        assertEquals(PaymentChannelClientState.State.READY, clientState.getState());
        assertEquals(2, multisigContract.getOutputs().size());   // One multi-sig, one change.
        Script script = multisigContract.getOutput(0).getScriptPubKey();
        assertTrue(script.isSentToMultiSig());
        script = multisigContract.getOutput(1).getScriptPubKey();
        assertTrue(script.isSentToAddress());
        assertTrue(wallet.getPendingTransactions().contains(multisigContract));

        // Provide the server with the multisig contract and simulate successful propagation/acceptance.
        serverState.provideMultiSigContract(multisigContract);
        assertEquals(PaymentChannelServerState.State.WAITING_FOR_MULTISIG_ACCEPTANCE, serverState.getState());
        multiSigFuture.set(broadcastMultiSig.getValue());
        assertEquals(PaymentChannelServerState.State.READY, serverState.getState());

        // Both client and server are now in the ready state, split the channel in half
        byte[] signature = clientState.incrementPaymentBy(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.subtract(BigInteger.ONE));
        BigInteger totalRefund = Utils.CENT.subtract(Transaction.REFERENCE_DEFAULT_MIN_TX_FEE.subtract(BigInteger.ONE));
        serverState.incrementPayment(totalRefund, signature);

        // We need to pay MIN_TX_FEE, but we only have MIN_NONDUST_OUTPUT
        try {
            serverState.close();
            fail();
        } catch (ValueOutOfRangeException e) {
            assertTrue(e.getMessage().contains("unable to pay required fee"));
        }

        // Now give the server enough coins to pay the fee
        StoredBlock block = new StoredBlock(makeSolvedTestBlock(blockStore, new ECKey().toAddress(params)), BigInteger.ONE, 1);
        Transaction tx1 = createFakeTx(params, Utils.COIN, serverKey.toAddress(params));
        serverWallet.receiveFromBlock(tx1, block, AbstractBlockChain.NewBlockType.BEST_CHAIN);

        // The contract is still not worth redeeming - its worth less than we pay in fee
        try {
            serverState.close();
            fail();
        } catch (ValueOutOfRangeException e) {
            assertTrue(e.getMessage().contains("more in fees than the channel was worth"));
        }

        signature = clientState.incrementPaymentBy(BigInteger.ONE.shiftLeft(1));
        totalRefund = totalRefund.subtract(BigInteger.ONE.shiftLeft(1));
        serverState.incrementPayment(totalRefund, signature);

        // And close the channel.
        serverState.close();
        assertEquals(PaymentChannelServerState.State.CLOSING, serverState.getState());
        Transaction closeTx = broadcastClose.getValue();
        closeFuture.set(closeTx);
        assertEquals(PaymentChannelServerState.State.CLOSED, serverState.getState());
        control.verify();
    }
}
