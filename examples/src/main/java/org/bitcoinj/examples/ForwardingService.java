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
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * ForwardingService demonstrates basic usage of the library. It connects to the network and when it receives coins,
 * simply sends them onwards to an address given on the command line.
 * TODO: Needs testing
 */
public class ForwardingService {
    static String usage = "Usage: address-to-send-back-to [mainnet|testnet|signet|regtest]";
    static final int requiredConfirmations = 1;
    private final BitcoinNetwork network;
    private final WalletAppKit kit;
    private Wallet wallet;

    public static void main(String[] args) {
        var out = System.out;
        BriefLogFormatter.init();   // Makes the log output more compact and easily read

        // Parse the address given as the 1st parameter and an optional network in the 2nd parameter
        BitcoinNetwork network = parseNetwork(args).orElseThrow();
        var forwardingAddress = Address.fromString(NetworkParameters.of(network), args[0]);

        out.printf("Network: %s (%s)\n", network, network.id());
        out.printf("Forwarding address: %s\n", forwardingAddress);

        // Create and start the Service (and WalletKit)
        var forwardingService = new ForwardingService(network);
        forwardingService.start();

        // Wait for coins to be received, a confirmation to be received, and the forwarded transaction to be broadcast
        CompletableFuture<Transaction> forwardedTxFuture = forwardingService.waitForCoins()
            // Incoming transaction received, now "compose" (i.e. chain) a call to wait for required confirmations
            .thenCompose(tx -> {
                // The transaction "tx" can either be pending, or included into a block (we didn't see the broadcast).
                Coin value = tx.getValueSentToMe(forwardingService.wallet);
                out.printf("Received tx for %s : %s\n", value.toFriendlyString(), tx);
                out.println("Transaction will be forwarded after it confirms.");
                return forwardingService.waitForConfirmation(tx);
            })
            // Required confirmations received, now compose a call to broadcast the forwarding transaction
            .thenCompose(confidence -> {
                out.printf("Incoming tx has received %d confirmations.", confidence.getDepthInBlocks());
                return forwardingService.forwardCoins(forwardingAddress);
            });

        // After we start listening, we can tell the user the receiving address
        out.printf("Waiting to receive coins on %s\n", forwardingService.receivingAddress());
        out.printf("Will send coins to %s\n", forwardingAddress);

        // Wait for the forwarding transaction to be broadcast or a {@code RuntimeException} if timeout or error
        forwardedTxFuture.orTimeout(1, TimeUnit.HOURS)
            .thenAccept(
                tx -> out.printf("Sent %s onwards! Transaction hash is %s\n", tx.getOutputSum().toFriendlyString(),  tx.getTxId())
            )
            .join();
    }
    
    /**
     * Forwarding service. Creating this object creates the {@link WalletAppKit} object.
     *
     * @param network Network to listen on
     */
    public ForwardingService(BitcoinNetwork network) {
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
     * Wait for the next coins received event.
     * TODO: Consider moving this to WalletAppKit or a Wallet interface
     * For this example app a timeout is provided by {@link CompletableFuture#orTimeout(long, TimeUnit)} in the
     * main method. There is no specific error handling for a {@link WalletCoinsReceivedEventListener} but blockchain
     * errors will be handled by the {@link WalletAppKit} or its component classes.
     * @return A future for the incoming (unconfirmed) transaction
     */
    CompletableFuture<Transaction> waitForCoins() {
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
     * TODO: Consider moving this to WalletAppKit or a Wallet interface
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

    /**
     * Forward the entire contents of the wallet to the forwarding address.
     * TODO: Consider moving this to WalletAppKit or a Wallet interface
     * @param forwardingAddress Address to forward to
     * @return A future for the broadcast transaction
     */
    CompletableFuture<Transaction> forwardCoins(Address forwardingAddress) {
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
     * @return The current receiving address of the forwarding wallet
     */
    public Address receivingAddress() {
        return wallet.currentReceiveAddress();
    }

    static Optional<BitcoinNetwork> parseNetwork(String[] args) {
        if (args.length < 1) {
            System.err.println(usage);
            return Optional.empty();
        }

        // Figure out which network we should connect to. Each network gets its own set of files.
        var networkString = (args.length > 1) ? args[1] : "mainnet";
        return BitcoinNetwork.fromString(networkString);
    }

    static String getPrefix(BitcoinNetwork network) {
        return String.format("forwarding-service-%s", network.toString());
    }
}
