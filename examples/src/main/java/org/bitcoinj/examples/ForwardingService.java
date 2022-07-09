/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
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
import org.bitcoinj.core.LegacyAddress;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.KeyChainGroupStructure;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener;

import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.MoreExecutors;

import java.io.File;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * ForwardingService demonstrates basic usage of the library. It sits on the network and when it receives coins, simply
 * sends them onwards to an address given on the command line.
 */
public class ForwardingService {
    static final int requiredConfirmations = 1;
    private final BitcoinNetwork network;
    private final NetworkParameters params;
    private final Address forwardingAddress;
    private final WalletAppKit kit;

    public static void main(String[] args) throws Exception {
        // This line makes the log output more compact and easily read, especially when using the JDK log adapter.
        BriefLogFormatter.init();
        if (args.length < 1) {
            System.err.println("Usage: address-to-send-back-to [regtest|testnet]");
            return;
        }

        // Figure out which network we should connect to. Each one gets its own set of files.
        BitcoinNetwork network;
        if (args.length > 1 && args[1].equals("testnet")) {
            network = BitcoinNetwork.TEST;
        } else if (args.length > 1 && args[1].equals("regtest")) {
            network = BitcoinNetwork.REGTEST;
        } else {
            network = BitcoinNetwork.MAIN;
        }
        // Parse the address given as the first parameter.
        var address = Address.fromString(NetworkParameters.of(network), args[0]);

        System.out.println("Network: " + network.id());
        System.out.println("Forwarding address: " + address);

        // Create the Service (and WalletKit)
        ForwardingService forwardingService = new ForwardingService(address, network);

        // Start the Service (and WalletKit)
        forwardingService.start();

        // Start listening and forwarding
        forwardingService.forward();
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
        this.params = NetworkParameters.of(network);

        // Start up a basic app using a class that automates some boilerplate.
        kit = new WalletAppKit(NetworkParameters.of(network),
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
    }

    /**
     * Setup the listener to forward received coins and wait
     */
    public void forward() {
        // We want to know when we receive money.
        kit.wallet().addCoinsReceivedEventListener((w, tx, prevBalance, newBalance) -> {
            // Runs in the dedicated "user thread" (see bitcoinj docs for more info on this).
            //
            // The transaction "tx" can either be pending, or included into a block (we didn't see the broadcast).
            Coin value = tx.getValueSentToMe(w);
            System.out.println("Received tx for " + value.toFriendlyString() + ": " + tx);
            System.out.println("Transaction will be forwarded after it confirms.");
            // Wait until it's made it into the block chain (may run immediately if it's already there).
            //
            // For this dummy app of course, we could just forward the unconfirmed transaction. If it were
            // to be double spent, no harm done. Wallet.allowSpendingUnconfirmedTransactions() would have to
            // be called in onSetupCompleted() above. But we don't do that here to demonstrate the more common
            // case of waiting for a block.

            tx.getConfidence().getDepthFuture(requiredConfirmations).whenComplete((result, t) -> {
                if (result != null) {
                    System.out.println("Confirmation received.");
                    forwardCoins();
                } else {
                    // This kind of future can't fail, just rethrow in case something weird happens.
                    throw new RuntimeException(t);
                }
            });
        });

        Address sendToAddress = LegacyAddress.fromKey(params, kit.wallet().currentReceiveKey());
        System.out.println("Send coins to: " + sendToAddress);
        System.out.println("Waiting for coins to arrive. Press Ctrl-C to quit.");

        try {
            Thread.sleep(Long.MAX_VALUE);
        } catch (InterruptedException ignored) {}
    }

    static String getPrefix(BitcoinNetwork network) {
        switch (network) {
            case TEST:      return "forwarding-service-testnet";
            case REGTEST:   return "forwarding-service-regtest";
            default:        return "forwarding-service";
        }
    }

    private void forwardCoins() {
        try {
            // Now send the coins onwards.
            SendRequest sendRequest = SendRequest.emptyWallet(forwardingAddress);
            Wallet.SendResult sendResult = kit.wallet().sendCoins(sendRequest);
            checkNotNull(sendResult);  // We should never try to send more coins than we have!
            System.out.println("Sending ...");
            // Register a callback that is invoked when the transaction has propagated across the network.
            sendResult.broadcastComplete.thenAccept(transaction -> {
                // The wallet has changed now, it'll get auto saved shortly or when the app shuts down.
                System.out.println("Sent coins onwards! Transaction hash is " + transaction.getTxId());
            });
        } catch (KeyCrypterException | InsufficientMoneyException e) {
            // We don't use encrypted wallets in this example - can never happen.
            throw new RuntimeException(e);
        }
    }
}
