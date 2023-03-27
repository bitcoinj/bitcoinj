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
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.Address;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.AddressParser;
import org.bitcoinj.core.Context;
import org.bitcoinj.base.DefaultAddressParser;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionBroadcast;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.CoinSelection;
import org.bitcoinj.wallet.CoinSelector;
import org.bitcoinj.wallet.KeyChainGroupStructure;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;

import java.io.Closeable;
import java.io.File;

import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.toList;

/**
 * ForwardingService demonstrates basic usage of the library. It sits on the network and when it receives coins, simply
 * sends them onwards to an address given on the command line.
 */
public class ForwardingService implements Closeable {
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
        AddressParser addressParser = new DefaultAddressParser();
        if (args.length >= 2) {
            // Verify address belongs to network
            network = BitcoinNetwork.fromString(args[1]).orElseThrow();
            address = addressParser.parseAddress(args[0], network);
        } else {
            // Infer network from address
            address = addressParser.parseAddressAnyNetwork(args[0]);
            network = (BitcoinNetwork) address.network();
        }

        forward(new File("."), network, address);
    }

    public static void forward(File directory, BitcoinNetwork network, Address address) {
        System.out.println("Network: " + network.id());
        System.out.println("Forwarding address: " + address);

        // Create the Service (and WalletKit)
        try (ForwardingService forwardingService = new ForwardingService(directory, address, network)) {
            // Start the Service (and WalletKit)
            Address receivingAddress = forwardingService.start();

            // After we start listening, we can tell the user the receiving address
            System.out.printf("Waiting to receive coins on: %s\n", receivingAddress);
            System.out.println("Press Ctrl-C to quit.");

            try {
                Thread.sleep(Long.MAX_VALUE);
            } catch (InterruptedException ignored) {}
        }
    }

    /**
     * Forwarding service. Creating this object creates the {@link WalletAppKit} object.
     *
     * @param directory directory for .wallet and .chain files
     * @param forwardingAddress forwarding destination
     * @param network Network to listen on
     */
    public ForwardingService(File directory, Address forwardingAddress, BitcoinNetwork network) {
        this.forwardingAddress = forwardingAddress;
        this.network = network;
        listener = this::coinsReceivedListener;
        // Start up a basic app using a class that automates some boilerplate.
        kit = new WalletAppKit(network,
                ScriptType.P2WPKH,
                KeyChainGroupStructure.BIP32,
                directory,
                getPrefix(network));
    }

    /**
     * Start the WalletAppKit
     * @return The receiving address for the forwarding wallet
     */
    public Address start() {
        if (network == BitcoinNetwork.REGTEST) {
            // Regression test mode is designed for testing and development only, so there's no public network for it.
            // If you pick this mode, you're expected to be running a local "bitcoind -regtest" instance.
            kit.connectToLocalHost();
        }

        kit.setBlockingStartup(false);  // Don't wait for blockchain synchronization before entering RUNNING state
        kit.startAsync();               // Connect to the network and start downloading transactions
        kit.awaitRunning();             // Wait for the service to reach the RUNNING state
        kit.peerGroup().setMaxConnections(MAX_CONNECTIONS);

        // Start listening and forwarding
        kit.wallet().addCoinsReceivedEventListener(listener);
        return kit.wallet().currentReceiveAddress();
    }

    /**
     * Close the service.
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
        kit.close();
    }

    /**
     * Implement the {@link WalletCoinsReceivedEventListener} functional interface. We could have {@link ForwardingService}
     * implement {@link WalletCoinsReceivedEventListener} with the {@code implements} keyword, but with JDK 8+ this method
     * can be private with any name and be referenced with a method reference.
     * @param wallet The active wallet
     * @param incomingTx the received transaction
     * @param prevBalance wallet balance before this transaction (unused)
     * @param newBalance wallet balance after this transaction (unused)
     */
    private void coinsReceivedListener(Wallet wallet, Transaction incomingTx, Coin prevBalance, Coin newBalance) {
        // Incoming transaction received, now "compose" (i.e. chain) a call to wait for required confirmations
        // The transaction "incomingTx" can either be pending, or included into a block (we didn't see the broadcast).
        Coin value = incomingTx.getValueSentToMe(wallet);
        System.out.printf("Received tx for %s : %s\n", value.toFriendlyString(), incomingTx);
        System.out.println("Transaction will be forwarded after it confirms.");
        System.out.println("Waiting for confirmation...");
        wallet.waitForConfirmations(incomingTx, REQUIRED_CONFIRMATIONS)
            .thenCompose(confidence -> {
                // Required confirmations received, now compose a call to broadcast the forwarding transaction
                System.out.printf("Incoming tx has received %d confirmations.\n", confidence.getDepthInBlocks());
                // Now send the coins onwards by sending exactly the outputs that have been sent to us
                SendRequest sendRequest = SendRequest.emptyWallet(forwardingAddress);
                sendRequest.coinSelector = forwardingCoinSelector(incomingTx.getTxId());
                System.out.printf("Creating outgoing transaction for %s...\n", forwardingAddress);
                return wallet.sendTransaction(sendRequest);
            })
            .thenCompose(broadcast -> {
                System.out.printf("Transaction %s is signed and is being delivered to %s...\n", broadcast.transaction().getTxId(), network);
                return broadcast.awaitRelayed().thenApply(TransactionBroadcast::transaction); // Wait until peers report they have seen the transaction
            })
            .thenAccept(tx ->
                System.out.printf("Sent %s onwards and acknowledged by peers, via transaction %s\n", tx.getOutputSum().toFriendlyString(), tx.getTxId())
            );
    }

    static String getPrefix(BitcoinNetwork network) {
        return String.format("forwarding-service-%s", network.toString());
    }

    /**
     * Create a CoinSelector that only returns outputs from a given parent transaction.
     * <p>
     * This is using the idea of partial function application to create a 2-argument function for coin selection
     * with a third, fixed argument of the transaction id.
     * @param parentTxId The parent transaction hash
     * @return a coin selector
     */
    static CoinSelector forwardingCoinSelector(Sha256Hash parentTxId) {
        return (target, candidates) -> candidates.stream()
                .filter(output -> output.getParentTransactionHash().equals(parentTxId))
                .collect(collectingAndThen(toList(), CoinSelection::new));
    }
}
