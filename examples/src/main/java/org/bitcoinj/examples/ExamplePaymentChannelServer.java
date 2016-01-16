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

import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;
import org.bitcoinj.core.Coin;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.VerificationException;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.protocols.channels.*;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.WalletExtension;

import com.google.common.collect.ImmutableList;

import com.google.common.util.concurrent.ListenableFuture;
import com.google.protobuf.ByteString;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.net.SocketAddress;
import java.util.List;

/**
 * Simple server that listens on port 4242 for incoming payment channels.
 */
public class ExamplePaymentChannelServer implements PaymentChannelServerListener.HandlerFactory {
    private static final org.slf4j.Logger log = LoggerFactory.getLogger(ExamplePaymentChannelServer.class);

    private WalletAppKit appKit;

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init();
        OptionParser parser = new OptionParser();
        OptionSpec<NetworkEnum> net = parser.accepts("net", "The network to run the examples on").withRequiredArg().ofType(NetworkEnum.class).defaultsTo(NetworkEnum.TEST);
        parser.accepts("help", "Displays program options");
        OptionSet opts = parser.parse(args);
        if (opts.has("help") || !opts.has(net)) {
            System.err.println("usage: ExamplePaymentChannelServer --net=MAIN/TEST/REGTEST");
            parser.printHelpOn(System.err);
            return;
        }
        NetworkParameters params = net.value(opts).get();
        new ExamplePaymentChannelServer().run(params);
    }

    public void run(NetworkParameters params) throws Exception {

        // Bring up all the objects we need, create/load a wallet, sync the chain, etc. We override WalletAppKit so we
        // can customize it by adding the extension objects - we have to do this before the wallet file is loaded so
        // the plugin that knows how to parse all the additional data is present during the load.
        appKit = new WalletAppKit(params, new File("."), "payment_channel_example_server") {
            @Override
            protected List<WalletExtension> provideWalletExtensions() {
                // The StoredPaymentChannelClientStates object is responsible for, amongst other things, broadcasting
                // the refund transaction if its lock time has expired. It also persists channels so we can resume them
                // after a restart.
                return ImmutableList.<WalletExtension>of(new StoredPaymentChannelServerStates(null));
            }
        };
        // Broadcasting can take a bit of time so we up the timeout for "real" networks
        final int timeoutSeconds = params.getId().equals(NetworkParameters.ID_REGTEST) ? 15 : 150;
        if (params == RegTestParams.get()) {
            appKit.connectToLocalHost();
        }
        appKit.startAsync();
        appKit.awaitRunning();

        System.out.println(appKit.wallet());

        // We provide a peer group, a wallet, a timeout in seconds, the amount we require to start a channel and
        // an implementation of HandlerFactory, which we just implement ourselves.
        new PaymentChannelServerListener(appKit.peerGroup(), appKit.wallet(), timeoutSeconds, Coin.valueOf(100000), this).bindAndStart(4242);
    }

    @Override
    public ServerConnectionEventHandler onNewConnection(final SocketAddress clientAddress) {
        // Each connection needs a handler which is informed when that payment channel gets adjusted. Here we just log
        // things. In a real app this object would be connected to some business logic.
        return new ServerConnectionEventHandler() {
            @Override
            public void channelOpen(Sha256Hash channelId) {
                log.info("Channel open for {}: {}.", clientAddress, channelId);

                // Try to get the state object from the stored state set in our wallet
                PaymentChannelServerState state = null;
                try {
                    StoredPaymentChannelServerStates storedStates = (StoredPaymentChannelServerStates)
                            appKit.wallet().getExtensions().get(StoredPaymentChannelServerStates.class.getName());
                    state = storedStates.getChannel(channelId).getOrCreateState(appKit.wallet(), appKit.peerGroup());
                } catch (VerificationException e) {
                    // This indicates corrupted data, and since the channel was just opened, cannot happen
                    throw new RuntimeException(e);
                }
                log.info("   with a maximum value of {}, expiring at UNIX timestamp {}.",
                        // The channel's maximum value is the value of the multisig contract which locks in some
                        // amount of money to the channel
                        state.getContract().getOutput(0).getValue(),
                        // The channel expires at some offset from when the client's refund transaction becomes
                        // spendable.
                        state.getExpiryTime() + StoredPaymentChannelServerStates.CHANNEL_EXPIRE_OFFSET);
            }

            @Override
            public ListenableFuture<ByteString> paymentIncrease(Coin by, Coin to, ByteString info) {
                log.info("Client {} paid increased payment by {} for a total of " + to.toString(), clientAddress, by);
                return null;
            }

            @Override
            public void channelClosed(PaymentChannelCloseException.CloseReason reason) {
                log.info("Client {} closed channel for reason {}", clientAddress, reason);
            }
        };
    }
}
