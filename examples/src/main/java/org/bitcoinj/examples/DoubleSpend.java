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

import org.bitcoinj.core.listeners.PreMessageReceivedEventListener;
import org.bitcoinj.core.*;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.utils.Threading;
import org.bitcoinj.wallet.Wallet;

import java.io.File;

import static org.bitcoinj.core.Coin.*;

/**
 * This is a little test app that waits for a coin on a local regtest node, then  generates two transactions that double
 * spend the same output and sends them. It's useful for testing double spend codepaths but is otherwise not something
 * you would normally want to do.
 */
public class DoubleSpend {
    public static void main(String[] args) throws Exception {
        BriefLogFormatter.init();
        final RegTestParams params = RegTestParams.get();
        WalletAppKit kit = new WalletAppKit(params, new File("."), "doublespend");
        kit.connectToLocalHost();
        kit.setAutoSave(false);
        kit.startAsync();
        kit.awaitRunning();

        System.out.println(kit.wallet());

        kit.wallet().getBalanceFuture(COIN, Wallet.BalanceType.AVAILABLE).get();
        Transaction tx1 = kit.wallet().createSend(Address.fromBase58(params, "muYPFNCv7KQEG2ZLM7Z3y96kJnNyXJ53wm"), CENT);
        Transaction tx2 = kit.wallet().createSend(Address.fromBase58(params, "muYPFNCv7KQEG2ZLM7Z3y96kJnNyXJ53wm"), CENT.add(SATOSHI.multiply(10)));
        final Peer peer = kit.peerGroup().getConnectedPeers().get(0);
        peer.addPreMessageReceivedEventListener(Threading.SAME_THREAD,
            new PreMessageReceivedEventListener() {
                @Override
                public Message onPreMessageReceived(Peer peer, Message m) {
                    System.err.println("Got a message!" + m.getClass().getSimpleName() + ": " + m);
                    return m;
                }
            }
        );
        peer.sendMessage(tx1);
        peer.sendMessage(tx2);

        Thread.sleep(5000);
        kit.stopAsync();
        kit.awaitTerminated();
    }
}
