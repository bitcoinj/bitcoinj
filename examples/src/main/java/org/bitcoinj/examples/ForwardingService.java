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
import org.bitcoinj.core.TransactionBroadcast;
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

/**
 * ForwardingService demonstrates basic usage of the library. It sits on the network and when it receives coins, simply
 * sends them onwards to an address given on the command line.
 */
public class ForwardingService implements AutoCloseable {
    static final String USAGE = "Usage: address-to-send-back-to [mainnet|testnet|signet|regtest]";
    static final int REQUIRED_CONFIRMATIONS = 1;
    static final int MAX_CONNECTIONS = 4;
    private final BitcoinNetwork network;
    private final Address forwardingAddress;
    private final WalletAppKit kit;
    private final WalletCoinsReceivedEventListener listener;

    public static void main(String[] args) {
        // This line makes the log output more compact and easily read, especially when using the JDK log adapter.
        BriefLogFormatter.init();
        Context.propagate(new Context());

        if (args.length < 1) {
            System.err.println(USAGE);
            throw new IllegalArgumentException("Address required");
        }

        // Figure out which network we should connect to. Each network gets its own set of files.
        Address address;
        BitcoinNetwork network;
        if (args.length >= 2) {
            // Verify address belongs to network
            network = BitcoinNetwork.fromString(args[1]).orElseThrow();
            address = Address.fromString(NetworkParameters.of(network), args[0]);
        } else {
            // Infer network from address
            address = Address.fromString(null, args[0]);
            network = address.network();
        }

        forward(network, address);
    }

    public static void forward(BitcoinNetwork network, Address address) {
        System.out.println("Network: " + network.id());
        System.out.println("Forwarding address: " + address);

        // Create the Service (and WalletKit)
        try (ForwardingService forwardingService = new ForwardingService(address, network)) {
            // Start the Service (and WalletKit)
            forwardingService.start();

            // After we start listening, we can tell the user the receiving address
            System.out.printf("Waiting to receive coins on %s\n", forwardingService.receivingAddress());
            System.out.printf("Will send coins to %s\n", address);
            System.out.println("Waiting for coins to arrive. Press Ctrl-C to quit.");

            try {
                Thread.sleep(Long.MAX_VALUE);
            } catch (InterruptedException ignored) {}
        }
    }

    /**
     * Forwarding service. Creating this object creates the {@link WalletAppKit} object.
     *
     * @param forwardingAddress forwarding destination
     * @param network Network to listen on
     */
    public ForwardingService(Address forwardingAddress, BitcoinNetwork network) {
        this.forwardingAddress = forwardingAddress;
        this.network = network;
        listener = this::coinsReceivedListener;
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
        kit.peerGroup().setMaxConnections(MAX_CONNECTIONS);

        // Start listening and forwarding
        kit.wallet().addCoinsReceivedEventListener(listener);
    }

    /**
     * Close the service. {@link AutoCloseable} will be triggered if an unhandled exception occurs within
     * a <i>try-with-resources</i> block.
     * <p>
     * Note that {@link WalletAppKit#setAutoStop(boolean)} is set by default and installs a shutdown handler
     * via {@link Runtime#addShutdownHook(Thread)} so we do not need to worry about explicitly shutting down
     * the {@code WalletAppKit} if the process is terminated.
     */
    @Override
    public void close() {
        if (kit.isRunning()) {
            kit.wallet().removeCoinsReceivedEventListener(listener);
        }
        kit.stopAsync();
    }

    /**
     * Implement the {@link WalletCoinsReceivedEventListener} functional interface. We could have {@link ForwardingService}
     * implement {@link WalletCoinsReceivedEventListener} with the {@code implements} keyword, but with JDK 8+ this method
     * can be private with any name and be referenced with a method reference.
     * @param wallet The active wallet (unused)
     * @param incomingTx the received transaction
     * @param prevBalance wallet balance before this transaction (unused)
     * @param newBalance wallet balance after this transaction (unused)
     */
    private void coinsReceivedListener(Wallet wallet, Transaction incomingTx, Coin prevBalance, Coin newBalance) {
        // Incoming transaction received, now "compose" (i.e. chain) a call to wait for required confirmations
        // The transaction "incomingTx" can either be pending, or included into a block (we didn't see the broadcast).
        Coin value = incomingTx.getValueSentToMe(kit.wallet());
        System.out.printf("Received tx for %s : %s\n", value.toFriendlyString(), incomingTx);
        System.out.println("Transaction will be forwarded after it confirms.");
        System.out.println("Waiting for confirmation...");
        waitForConfirmation(incomingTx)
            .thenCompose(confidence -> {
                // Required confirmations received, now compose a call to broadcast the forwarding transaction
                System.out.printf("Incoming tx has received %d confirmations.\n", confidence.getDepthInBlocks());
                // Now send the coins onwards by sending the entire contents of our wallet
                SendRequest sendRequest = SendRequest.emptyWallet(forwardingAddress);
                System.out.printf("Creating outgoing transaction for %s...\n", forwardingAddress);
                return sendTransaction(sendRequest);
            })
            .thenCompose(broadcast -> {
                System.out.printf("Transaction %s is signed and is being delivered to %s...\n", broadcast.transaction().getTxId(), network);
                return broadcast.future(); // Return a future that completes when Peers report they have seen the transaction
            })
            .thenAccept(tx ->
                System.out.printf("Sent %s onwards and acknowledged by peers, via transaction %s\n", tx.getOutputSum().toFriendlyString(), tx.getTxId())
            );
    }

    /**
     * Wait for confirmation on a transaction.
     * <p>
     * TODO: Consider changing this so that the returned object contains a reference to the actual transaction rather than just its hash (id)
     * <p>
     * TODO: Consider adding this method (or equivalent) to the main bitcoinj API (Wallet or other class)
     * @param tx the transaction we are waiting for
     * @return a future for an object that contains transaction confidence information
     */
    CompletableFuture<TransactionConfidence> waitForConfirmation(Transaction tx) {
        return tx.getConfidence().getDepthFuture(REQUIRED_CONFIRMATIONS);
    }

    /**
     * Initiate sending the transaction in a {@link SendRequest}. Calls {@link Wallet#sendCoins(SendRequest)} which
     * performs the following significant operations internally:
     * <ol>
     *     <li>{@link Wallet#completeTx(SendRequest)} -- calculate change and sign</li>
     *     <li>{@link Wallet#commitTx(Transaction)} -- puts the transaction in the {@code Wallet}'s pending pool</li>
     *     <li>{@link org.bitcoinj.core.TransactionBroadcaster#broadcastTransaction(Transaction)} typically implemented by {@link org.bitcoinj.core.PeerGroup#broadcastTransaction(Transaction)} -- queues requests to send the transaction to a determined number of {@code Peer}s</li>
     * </ol>
     * Note that this method will <i>complete</i> and return a {@link TransactionBroadcast} <i>before</i> the broadcast actually occurs. The broadcast process includes the following steps:
     * <ol>
     *     <li>Wait until enough {@link org.bitcoinj.core.Peer}s are connected.</li>
     *     <li>Broadcast the transaction by a determined number of {@link org.bitcoinj.core.Peer}s</li>
     *     <li>Wait for confirmation from a determined number of remote peers that they have received the broadcast</li>
     *     <li>Mark {@link TransactionBroadcast#future()} as complete</li>
     * </ol>
     * Note: There is a pending PR (#2548) which will make available an additional {@link CompletableFuture} that will complete
     * after step 3 above. When and if that PR is merged, this method should probably return that future.
     * <p>
     * TODO: Check the status of PR #2548
     * <p>
     * TODO: Consider adding this method (or equivalent) to the Wallet class
     * @param sendRequest transaction to send
     * @return A future for the transaction broadcast
     */
    CompletableFuture<TransactionBroadcast> sendTransaction(SendRequest sendRequest) {
        CompletableFuture<TransactionBroadcast> future = new CompletableFuture<>();
        try {
            // Complete successfully when the transaction is ready to be sent to peers.
            future.complete(kit.wallet().sendCoins(sendRequest).broadcast);
        } catch (KeyCrypterException | InsufficientMoneyException e) {
            // We should never try to send more coins than we have, if we do we get an InsufficientMoneyException
            // We don't use encrypted wallets in this example - KeyCrypterException can never happen.
            future.completeExceptionally(e);
        }
        return future;
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
