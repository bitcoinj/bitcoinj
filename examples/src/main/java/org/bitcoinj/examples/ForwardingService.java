/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
 * Copyright 2022 Sean Gilligan
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

package org.bitcoinj.examples;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.KeyChainGroupStructure;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;

import java.io.File;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * ForwardingService demonstrates basic usage of the library. It connects to the network and when it receives coins,
 * simply sends them onwards to an address given on the command line.
 * TODO: Needs testing
 */
public class ForwardingService {
    static final int requiredConfirmations = 1;
    private final BitcoinNetwork network;
    private final Address forwardingAddress;
    private final WalletAppKit kit;
    private Wallet wallet;

    public static void main(String[] args) {
        // This line makes the log output more compact and easily read, especially when using the JDK log adapter.
        BriefLogFormatter.init();
        if (args.length < 1) {
            System.err.println("Usage: address-to-send-back-to [mainnet|testnet|signet|regtest]");
            return;
        }

        // Figure out which network we should connect to. Each network gets its own set of files.
        String networkArgument = (args.length > 1) ? args[1] : "main";
        BitcoinNetwork network = BitcoinNetwork.fromString(networkArgument).orElseThrow();

        // Parse the address given as the first parameter.
        var address = Address.fromString(NetworkParameters.of(network), args[0]);

        System.out.printf("Network: %s (%s)\n", network, network.id());
        System.out.printf("Forwarding address: %s\n", address);

        // Create the Service (and WalletKit)
        ForwardingService forwardingService = new ForwardingService(address, network);

        // Start the Service (and WalletKit)
        forwardingService.start();

        // Start listening and forwarding
        CompletableFuture<Transaction> forwardedTxFuture = forwardingService.forward();

        System.out.printf("Wallet will receive coins on %s\n", forwardingService.receivingAddress());
        System.out.printf("Will send coins to %s\n", address);
        System.out.println("Waiting for coins to arrive. Press Ctrl-C to quit.");

        // Wait for the forwarding transaction to be broadcast or a {@code RuntimeException} if timeout or error
        forwardedTxFuture.orTimeout(1, TimeUnit.HOURS)
                .thenAccept(tx -> System.out.printf("Sent %s onwards! Transaction hash is %s\n", tx.getOutputSum().toFriendlyString(),  tx.getTxId()))
                .join();
    }
    
    /**
     * Forwarding service. Creating this object creates the {@link WalletAppKit} object.
     *
     * @param forwardingAddress Address to forward to
     * @param network Network to listen on
     */
    public ForwardingService(Address forwardingAddress, BitcoinNetwork network) {
        this.forwardingAddress = forwardingAddress;
        this.network = network;

        // Start up a basic app using a class that automates some boilerplate.
        kit = new WalletAppKit(network,
                ScriptType.P2WPKH,
                KeyChainGroupStructure.BIP32,
                new File("."),
                getPrefix(network));
    }

    /**
     * Start the WalletAppKit
     */
    public void start() {
        if (network == BitcoinNetwork.REGTEST) {
            // Regression test mode is designed for testing and development only, so there's no public network for it.
            // If you pick this mode, you're expected to be running a local "bitcoind -regtest" instance.
            kit.connectToLocalHost();
        }

        // Download the blockchain and wait until it's done.
        kit.startAsync();
        kit.awaitRunning();
        wallet = kit.wallet();
    }

    /**
     * @return The current receiving address of the forwarding wallet
     */
    public Address receivingAddress() {
        return wallet.currentReceiveAddress();
    }

    /**
     * Setup a listener that will forward received coins and return a transaction
     * @return A future for the broadcasted forwarding Transaction
     */
    public CompletableFuture<Transaction> forward() {
        // Wait for coins to be received, a confirmation of 1 block to be received, and the coins to be forwarded
        return waitForCoins(wallet)
                .whenComplete(this::logCoinsPendingComplete)
                // Incoming transaction received, now "compose" (i.e. chain) a call to wait for required confirmations
                .thenCompose(this::waitForConfirmation)
                .whenComplete(this::logConfirmationComplete)
                // Required confirmations received, now compose/chain a call to broadcast the forwarding transaction
                .thenCompose(c -> this.forwardCoins());
    }

    /**
     * Wait for the next coins received event.
     * For this example app a timeout is provided by {@link CompletableFuture#orTimeout(long, TimeUnit)} in the
     * main method. There is no specific error handling for a {@link WalletCoinsReceivedEventListener} but blockchain
     * errors will be handled by the {@link WalletAppKit} or its component classes.
     * @param wallet wallet that is waiting
     * @return A future for the incoming (unconfirmed) transaction
     */
    CompletableFuture<Transaction> waitForCoins(Wallet wallet) {
        final CompletableFuture<Transaction> txFuture = new CompletableFuture<>();
        final WalletCoinsReceivedEventListener listener = (w, tx, prevBalance, newBalance) -> {
            // Runs in the dedicated "user thread" (see bitcoinj docs for more info on this).
            // For this sample app timeout is provided by {
            txFuture.complete(tx);
        };
        wallet.addCoinsReceivedEventListener(listener);
        return txFuture.whenComplete((tx, err) ->
            wallet.removeCoinsReceivedEventListener(listener)
        );
    }

    /**
     * Wait for confirmation on a transaction.
     * @param transaction the transaction we are waiting for
     * @return a future for a TransactionConfidence object
     */
    CompletableFuture<TransactionConfidence> waitForConfirmation(Transaction transaction) {
        // Wait until transaction has been confirmed into the blockchain (this may run immediately if it's already there).
        //
        // For this dummy app of course, we could just forward the unconfirmed transaction. If it were
        // to be double spent, no harm done. Wallet.allowSpendingUnconfirmedTransactions() would have to
        // be called in onSetupCompleted() above. But we don't do that here to demonstrate the more common
        // case of waiting for a block.
        return transaction.getConfidence().getDepthFuture(requiredConfirmations);
    }

    static String getPrefix(BitcoinNetwork network) {
        return String.format("forwarding-service-%s", network.toString());
    }

    /**
     * Forward the entire contents of the wallet to the forwarding address.
     * @return A future for the broadcast transaction
     */
    CompletableFuture<Transaction> forwardCoins() {
        // Now send the coins onwards by sending the entire contents of our wallet
        SendRequest sendRequest = SendRequest.emptyWallet(forwardingAddress);
        try {
            // Complete successfully when the transaction has propagated across the network.
            return wallet.sendCoins(sendRequest).broadcastComplete;
        } catch (KeyCrypterException | InsufficientMoneyException e) {
            // We should never try to send more coins than we have, if we do we get an InsufficientMoneyException
            // We don't use encrypted wallets in this example - KeyCrypterException can never happen.
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Completion handler for coins received
     * @param incomingTx transaction received or null (if {@code err != null})
     * @param throwable exception or null
     */
    void logCoinsPendingComplete(Transaction incomingTx, Throwable throwable) {
        if (throwable == null) {
            // The transaction "incomingTx" can either be pending, or included into a block (we didn't see the broadcast).
            Coin value = incomingTx.getValueSentToMe(wallet);
            System.out.println("Received tx for " + value.toFriendlyString() + ": " + incomingTx);
            System.out.println("Transaction will be forwarded after it confirms.");
        } else {
            System.out.println("Error: " + throwable);
        }
    }

    /**
     * Completion handler for transaction confirmation(s) received
     * @param confidence transaction confidence object (if {@code err != null})
     * @param throwable exception or null
     */
    void logConfirmationComplete(TransactionConfidence confidence, Throwable throwable) {
        if (throwable == null) {
            System.out.printf("Incoming tx has received %d confirmations.", confidence.getDepthInBlocks());
        } else {
            System.out.println("Error: " + throwable);
        }
    }
}
