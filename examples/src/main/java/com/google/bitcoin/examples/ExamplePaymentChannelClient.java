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

package com.google.bitcoin.examples;

import com.google.bitcoin.core.*;
import com.google.bitcoin.kits.WalletAppKit;
import com.google.bitcoin.params.TestNet3Params;
import com.google.bitcoin.protocols.channels.PaymentChannelClientConnection;
import com.google.bitcoin.protocols.channels.StoredPaymentChannelClientStates;
import com.google.bitcoin.protocols.channels.ValueOutOfRangeException;
import com.google.bitcoin.utils.BriefLogFormatter;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.util.concurrent.CountDownLatch;

import static com.google.bitcoin.core.Utils.CENT;
import static java.math.BigInteger.TEN;
import static java.math.BigInteger.ZERO;

/**
 * Simple client that connects to the given host, opens a channel, and pays one cent.
 */
public class ExamplePaymentChannelClient {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(ExamplePaymentChannelClient.class);
    private WalletAppKit appKit;
    private final BigInteger channelSize;
    private final ECKey myKey;
    private final NetworkParameters params;

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init();
        System.out.println("USAGE: host");
        new ExamplePaymentChannelClient().run(args[0]);
    }

    public ExamplePaymentChannelClient() {
        channelSize = CENT;
        myKey = new ECKey();
        params = TestNet3Params.get();
    }

    public void run(final String host) throws Exception {
        // Bring up all the objects we need, create/load a wallet, sync the chain, etc. We override WalletAppKit so we
        // can customize it by adding the extension objects - we have to do this before the wallet file is loaded so
        // the plugin that knows how to parse all the additional data is present during the load.
        appKit = new WalletAppKit(params, new File("."), "payment_channel_example_client") {
            @Override
            protected void addWalletExtensions() {
                // The StoredPaymentChannelClientStates object is responsible for, amongst other things, broadcasting
                // the refund transaction if its lock time has expired. It also persists channels so we can resume them
                // after a restart.
                wallet().addExtension(new StoredPaymentChannelClientStates(wallet(), peerGroup()));
            }
        };
        appKit.startAndWait();
        // We now have active network connections and a fully synced wallet.
        // Add a new key which will be used for the multisig contract.
        appKit.wallet().addKey(myKey);
        appKit.wallet().allowSpendingUnconfirmedTransactions();

        System.out.println(appKit.wallet());

        // Create the object which manages the payment channels protocol, client side. Tell it where the server to
        // connect to is, along with some reasonable network timeouts, the wallet and our temporary key. We also have
        // to pick an amount of value to lock up for the duration of the channel.
        //
        // Note that this may or may not actually construct a new channel. If an existing unclosed channel is found in
        // the wallet, then it'll re-use that one instead.
        final int timeoutSecs = 15;
        final InetSocketAddress server = new InetSocketAddress(host, 4242);

        waitForSufficientBalance(channelSize);
        final String channelID = host;
        // Do this twice as each one sends 1/10th of a bitcent 5 times, so to send a bitcent, we do it twice. This
        // demonstrates resuming a channel that wasn't closed yet. It should close automatically once we run out
        // of money on the channel.
        log.info("Round one ...");
        openAndSend(timeoutSecs, server, channelID);
        log.info("Round two ...");
        log.info(appKit.wallet().toString());
        openAndSend(timeoutSecs, server, channelID);
        log.info("Waiting ...");
        Thread.sleep(60 * 60 * 1000);  // 1 hour.
        log.info("Stopping ...");
        appKit.stopAndWait();
    }

    private void openAndSend(int timeoutSecs, InetSocketAddress server, String channelID) throws IOException, ValueOutOfRangeException, InterruptedException {
        PaymentChannelClientConnection client = new PaymentChannelClientConnection(
                server, timeoutSecs, appKit.wallet(), myKey, channelSize, channelID);
        // Opening the channel requires talking to the server, so it's asynchronous.
        final CountDownLatch latch = new CountDownLatch(1);
        Futures.addCallback(client.getChannelOpenFuture(), new FutureCallback<PaymentChannelClientConnection>() {
            @Override
            public void onSuccess(PaymentChannelClientConnection client) {
                // Success! We should be able to try making micropayments now. Try doing it 5 times.
                for (int i = 0; i < 5; i++) {
                    try {
                        client.incrementPayment(CENT.divide(TEN));
                    } catch (ValueOutOfRangeException e) {
                        log.error("Failed to increment payment by a CENT, remaining value is {}", client.state().getValueRefunded());
                        System.exit(-3);
                    }
                    log.info("Successfully sent payment of one CENT, total remaining on channel is now {}", client.state().getValueRefunded());
                }
                if (client.state().getValueRefunded().equals(ZERO)) {
                    // Now tell the server we're done so they should broadcast the final transaction and refund us what's
                    // left. If we never do this then eventually the server will time out and do it anyway and if the
                    // server goes away for longer, then eventually WE will time out and the refund tx will get broadcast
                    // by ourselves.
                    log.info("Closing channel for good");
                    client.close();
                } else {
                    // Just unplug from the server but leave the channel open so it can resume later.
                    client.disconnectWithoutChannelClose();
                }
                latch.countDown();
            }

            @Override
            public void onFailure(Throwable throwable) {
                log.error("Failed to open connection", throwable);
                latch.countDown();
            }
        });
        latch.await();
    }

    private void waitForSufficientBalance(BigInteger amount) {
        // Not enough money in the wallet.
        BigInteger amountPlusFee = amount.add(Wallet.SendRequest.DEFAULT_FEE_PER_KB);
        // ESTIMATED because we don't really need to wait for confirmation.
        ListenableFuture<BigInteger> balanceFuture = appKit.wallet().getBalanceFuture(amountPlusFee, Wallet.BalanceType.ESTIMATED);
        if (!balanceFuture.isDone()) {
            System.out.println("Please send " + Utils.bitcoinValueToFriendlyString(amountPlusFee) +
                    " BTC to " + myKey.toAddress(params));
            Futures.getUnchecked(balanceFuture);
        }
    }
}
