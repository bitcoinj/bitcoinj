/*
 * Copyright by the original author or authors.
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
import org.bitcoinj.core.Context;
import org.bitcoinj.core.InsufficientMoneyException;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.KeyChainGroupStructure;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;

import java.io.File;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * ForwardingService demonstrates basic usage of the library. It sits on the network and when it receives coins, simply
 * sends them onwards to an address given on the command line and then terminates.
 * TODO: Needs testing
 * TODO: Should probably be renamed now that it sends once and terminates.
 */
public class ForwardingService {
    static final String usage = "Usage: address-to-send-back-to [mainnet|testnet|signet|regtest]";
    static final int requiredConfirmations = 1;
    private final WalletAppKit kit;

    public static void main(String[] args) {
        // This line makes the log output more compact and easily read, especially when using the JDK log adapter.
        BriefLogFormatter.init();
        Context.propagate(new Context());

        if (args.length < 1) {
            System.err.println(usage);
            throw new IllegalArgumentException("Address required");
        }

        // Figure out which network we should connect to. Each network gets its own set of files.
        var networkString = (args.length > 1) ? args[1] : "mainnet";
        var network = BitcoinNetwork.fromString(networkString).orElseThrow();
        var address = Address.fromString(NetworkParameters.of(network), args[0]);

        forward(network, address);
    }

    public static void forward(BitcoinNetwork network, Address address) {
        System.out.println("Network: " + network.id());
        System.out.println("Forwarding address: " + address);

        // Create the Service (and WalletKit)
        ForwardingService forwardingService = new ForwardingService(network);

        // Start the Service (and WalletKit)
        forwardingService.start();

        // Start listening and forwarding
        CompletableFuture<Transaction> forwardedTxFuture = forwardingService.waitForCoins()
            .thenCompose(tx -> {
                // Incoming transaction received, now "compose" (i.e. chain) a call to wait for required confirmations
                // The transaction "tx" can either be pending, or included into a block (we didn't see the broadcast).
                Coin value = tx.getValueSentToMe(forwardingService.kit.wallet());
                System.out.printf("Received tx for %s : %s\n", value.toFriendlyString(), tx);
                System.out.println("Transaction will be forwarded after it confirms.");
                return forwardingService.waitForConfirmation(tx);
            })
            .thenCompose(confidence -> {
                // Required confirmations received, now compose a call to broadcast the forwarding transaction
                System.out.printf("Incoming tx has received %d confirmations.", confidence.getDepthInBlocks());
                return forwardingService.forwardCoins(address);
            });

        // After we start listening, we can tell the user the receiving address
        System.out.printf("Waiting to receive coins on %s\n", forwardingService.receivingAddress());
        System.out.printf("Will send coins to %s\n", address);

        // Wait for the forwarding transaction to be broadcast or a {@code RuntimeException} if timeout or error
        forwardedTxFuture.orTimeout(1, TimeUnit.HOURS)
            .thenAccept(
                tx -> System.out.printf("Sent %s onwards! Transaction hash is %s\n", tx.getOutputSum().toFriendlyString(),  tx.getTxId())
            )
            .join();
    }

    /**
     * Forwarding service. Creating this object creates the {@link WalletAppKit} object.
     *
     * @param network Network to listen on
     */
    public ForwardingService(BitcoinNetwork network) {
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
        if (kit.wallet().getNetworkParameters().network() == BitcoinNetwork.REGTEST) {
            // Regression test mode is designed for testing and development only, so there's no public network for it.
            // If you pick this mode, you're expected to be running a local "bitcoind -regtest" instance.
            kit.connectToLocalHost();
        }

        // Download the blockchain and wait until it's done.
        kit.startAsync();
        kit.awaitRunning();
    }

    /**
     * Setup the listener to forward received coins and wait
     */
    CompletableFuture<Transaction> waitForCoins() {
        final CompletableFuture<Transaction> txFuture = new CompletableFuture<>();
        // We want to know when we receive money.
        final WalletCoinsReceivedEventListener listener = (w, tx, prevBalance, newBalance) -> {
            // Runs in the dedicated "user thread" (see bitcoinj docs for more info on this).
            txFuture.complete(tx);
        };
        kit.wallet().addCoinsReceivedEventListener(listener);
        return txFuture.whenComplete((tx, err) ->
            kit.wallet().removeCoinsReceivedEventListener(listener)
        );
    }

    /**
     * Wait for confirmation on a transaction.
     * @param tx the transaction we are waiting for
     */
    CompletableFuture<TransactionConfidence> waitForConfirmation(Transaction tx) {
        return tx.getConfidence().getDepthFuture(requiredConfirmations);
    }

    /**
     * Forward the entire contents of the wallet to the forwarding address.
     * @param forwardingAddress Address to forward to
     * @return A future for the broadcast transaction
     */
    CompletableFuture<Transaction> forwardCoins(Address forwardingAddress) {
        // Now send the coins onwards by sending the entire contents of our wallet
        SendRequest sendRequest = SendRequest.emptyWallet(forwardingAddress);
        try {
            // Complete successfully when the transaction has propagated across the network.
            return kit.wallet().sendCoins(sendRequest).broadcastComplete;
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
        return kit.wallet().currentReceiveAddress();
    }

    static String getPrefix(BitcoinNetwork network) {
        return String.format("forwarding-service-%s", network.toString());
    }
}
