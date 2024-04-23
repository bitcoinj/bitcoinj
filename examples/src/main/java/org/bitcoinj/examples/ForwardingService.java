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
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.AddressParser;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionBroadcast;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.CoinSelection;
import org.bitcoinj.wallet.CoinSelector;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;

import java.io.Closeable;
import java.io.File;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;

/**
 * ForwardingService demonstrates basic usage of bitcoinj. It creates an SPV Wallet, listens on the network
 * and when it receives coins, simply sends them onwards to the address given on the command line.
 */
public class ForwardingService implements Closeable {
    static private final String NETS = String.join("|", BitcoinNetwork.strings());
    static final String USAGE = String.format("Usage: address-to-forward-to [%s]", NETS);

    /**
     * Create a Wallet and run the forwarding service as a command line tool
     * @param args See {@link #USAGE}
     */
    public static void main(String[] args) throws InterruptedException {
        // This line makes the log output more compact and easily read, especially when using the JDK log adapter.
        BriefLogFormatter.init();
        Context.propagate(new Context());

        Config config = parse(args);

        System.out.println("Network: " + config.network);
        System.out.println("Forwarding address: " + config.forwardingAddress);

        // Create the service, which will listen for transactions and forward coins until closed
        try (ForwardingService forwardingService = new ForwardingService(config)) {
            // After we start listening, we can tell the user the receiving address
            System.out.println(forwardingService.status());
            System.out.println("Press Ctrl-C to quit.");

            // Wait for Control-C
            Thread.sleep(Long.MAX_VALUE);
        }
    }

    private final Config config;
    private final Wallet wallet;
    private final WalletAppKit walletAppKit;

    /**
     * Create and start the WalletKit and adding a listener to the wallet.
     * Note that {@link WalletAppKit#setAutoStop(boolean)} is set by default and installs a shutdown handler
     * via {@link Runtime#addShutdownHook(Thread)} so we do not need to worry about explicitly shutting down
     * the {@code WalletAppKit} if the process is terminated.
     * @param config the configuration to use
     */
    public ForwardingService(Config config) {
        this.config = config;
        walletAppKit = WalletAppKit.launch(config.network, config.walletDirectory, config.walletPrefix, config.maxConnections);
        wallet = walletAppKit.wallet();
        // Add a listener that forwards received coins
        wallet.addCoinsReceivedEventListener(this::coinForwardingListener);
    }

    /**
     * A listener to receive coins and forward them to the configured address.
     * Implements the {@link WalletCoinsReceivedEventListener} functional interface.
     * @param wallet The active wallet
     * @param incomingTx the received transaction
     * @param prevBalance wallet balance before this transaction (unused)
     * @param newBalance wallet balance after this transaction (unused)
     */
    void coinForwardingListener(Wallet wallet, Transaction incomingTx, Coin prevBalance, Coin newBalance) {
        // Incoming transaction received, now "compose" (i.e. chain) a call to wait for required confirmations
        // The transaction "incomingTx" can either be pending, or included into a block (we didn't see the broadcast).
        Coin value = incomingTx.getValueSentToMe(wallet);
        System.out.printf("Received tx for %s : %s\n", value.toFriendlyString(), incomingTx);
        System.out.println("Transaction will be forwarded after it confirms.");
        System.out.println("Waiting for confirmation...");
        wallet.waitForConfirmations(incomingTx, config.requiredConfirmations)
            .thenCompose(confidence -> {
                // Required confirmations received, now create and send forwarding transaction
                System.out.printf("Incoming tx has received %d confirmations.\n", confidence.getDepthInBlocks());
                return forward(wallet, incomingTx, config.forwardingAddress);
            })
            .whenComplete((broadcast, throwable) -> {
                if (broadcast != null) {
                    System.out.printf("Sent %s onwards and acknowledged by peers, via transaction %s\n",
                            broadcast.transaction().getOutputSum().toFriendlyString(),
                            broadcast.transaction().getTxId());
                } else {
                    System.out.println("Exception occurred: "  + throwable);
                }
            });
    }

    /**
     * Forward an incoming transaction by creating a new transaction, signing, and sending to the specified address. The
     * inputs for the new transaction should only come from the incoming transaction, so we use a custom {@link CoinSelector}
     * that only selects wallet UTXOs with the correct parent transaction ID.
     * @param wallet The active wallet
     * @param incomingTx the received transaction
     * @param forwardingAddress the address to send to
     * @return A future for a TransactionBroadcast object that completes when relay is acknowledged by peers
     */
    CompletableFuture<TransactionBroadcast> forward(Wallet wallet, Transaction incomingTx, Address forwardingAddress) {
        // Send coins received in incomingTx onwards by sending exactly the UTXOs we have just received.
        // We're not truly emptying the wallet because we're limiting the available outputs with a CoinSelector.
        SendRequest sendRequest = SendRequest.emptyWallet(forwardingAddress);
        // Use a CoinSelector that only returns wallet UTXOs from the incoming transaction.
        sendRequest.coinSelector = CoinSelector.fromPredicate(output -> Objects.equals(output.getParentTransactionHash(), incomingTx.getTxId()));
        System.out.printf("Creating outgoing transaction for %s...\n", forwardingAddress);
        return wallet.sendTransaction(sendRequest)
                .thenCompose(broadcast -> {
                    System.out.printf("Transaction %s is signed and is being delivered to %s...\n", broadcast.transaction().getTxId(), wallet.network());
                    return broadcast.awaitRelayed(); // Wait until peers report they have seen the transaction
                });
    }

    String status() {
        return String.format("Waiting to receive coins on: %s", wallet.currentReceiveAddress());
    }

    /**
     * Close the service.
     */
    @Override
    public void close() {
        wallet.removeCoinsReceivedEventListener(this::coinForwardingListener);
        walletAppKit.close();
    }

    public record Config(BitcoinNetwork network,        // Network to operate on
                         Address forwardingAddress,     // Address to forward to
                         File walletDirectory,          // Directory to create wallet files in
                         String walletPrefix,           // Prefix for wallet file names
                         int requiredConfirmations,     // Required number of tx confirmations before forwarding
                         int maxConnections)            // Maximum number of Peer connections
    {
        static final int REQUIRED_CONFIRMATIONS = 1;
        static final int MAX_CONNECTIONS = 4;
        Config(BitcoinNetwork network, Address forwardingAddress) {
            this(network, forwardingAddress, new File("."), getPrefix(network), REQUIRED_CONFIRMATIONS, MAX_CONNECTIONS);
        }
    }

    static Config parse(String[] args) {
        if (args.length < 1 || args.length > 2) {
            System.err.println(USAGE);
            System.exit(1);
        }
        BitcoinNetwork network;
        Address forwardingAddress;

        if (args.length >= 2) {
            // If network was specified, validate address against network
            network = BitcoinNetwork.fromString(args[1]).orElseThrow();
            forwardingAddress = AddressParser.getDefault(network).parseAddress(args[0]);
        } else {
            // Else network not-specified, extract network from address
            forwardingAddress = AddressParser.getDefault().parseAddress(args[0]);
            network = (BitcoinNetwork) forwardingAddress.network();
        }
        return new Config(network, forwardingAddress);
    }

    static String getPrefix(BitcoinNetwork network) {
        return String.format("forwarding-service-%s", network.toString());
    }
}
