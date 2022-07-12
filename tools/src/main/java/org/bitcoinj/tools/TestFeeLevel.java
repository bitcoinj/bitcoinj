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

package org.bitcoinj.tools;

import org.bitcoinj.base.Coin;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.*;
import org.bitcoinj.core.listeners.PeerConnectedEventListener;
import org.bitcoinj.core.listeners.PeerDisconnectedEventListener;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.utils.BriefLogFormatter;
import org.bitcoinj.wallet.KeyChainGroupStructure;
import org.bitcoinj.wallet.SendRequest;
import org.bitcoinj.wallet.Wallet;

import java.io.File;
import java.util.concurrent.ExecutionException;

/**
 * A program that sends a transaction with the specified fee and measures how long it takes to confirm.
 */
public class TestFeeLevel {

    private static final MainNetParams PARAMS = MainNetParams.get();
    private static final int NUM_OUTPUTS = 2;
    private static WalletAppKit kit;

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.initWithSilentBitcoinJ();
        if (args.length == 0) {
            System.err.println("Specify the fee rate to test in satoshis/kB as the first argument.");
            return;
        }

        Coin feeRateToTest = Coin.valueOf(Long.parseLong(args[0]));
        System.out.println("Fee rate to test is " + feeRateToTest.toFriendlyString() + "/kB");

        kit = new WalletAppKit(PARAMS.network(), ScriptType.P2WPKH, KeyChainGroupStructure.BIP32, new File("."), "testfeelevel");
        kit.startAsync();
        kit.awaitRunning();
        try {
            go(feeRateToTest, NUM_OUTPUTS);
        } finally {
            kit.stopAsync();
            kit.awaitTerminated();
        }
    }

    private static void go(Coin feeRateToTest, int numOutputs) throws InterruptedException, ExecutionException, InsufficientMoneyException {
        System.out.println("Wallet has " + kit.wallet().getBalance().toFriendlyString()
                + "; current receive address is " + kit.wallet().currentReceiveAddress());

        kit.peerGroup().setMaxConnections(25);

        if (kit.wallet().getBalance().compareTo(feeRateToTest) < 0) {
            System.out.println("Send some coins to receive address and wait for it to confirm ...");
            kit.wallet().getBalanceFuture(feeRateToTest, Wallet.BalanceType.AVAILABLE).get();
        }

        int heightAtStart = kit.chain().getBestChainHeight();
        System.out.println("Height at start is " + heightAtStart);

        Coin value = kit.wallet().getBalance().divide(2); // Keep a chunk for the fee.
        Coin outputValue = value.divide(numOutputs);
        Transaction transaction = new Transaction(PARAMS);
        for (int i = 0; i < numOutputs - 1; i++) {
            transaction.addOutput(outputValue, kit.wallet().freshReceiveAddress());
            value = value.subtract(outputValue);
        }
        transaction.addOutput(value, kit.wallet().freshReceiveAddress());
        SendRequest request = SendRequest.forTx(transaction);
        request.feePerKb = feeRateToTest;
        request.ensureMinRequiredFee = false;
        kit.wallet().completeTx(request);
        System.out.println("Size in bytes is " + request.tx.unsafeBitcoinSerialize().length);
        System.out.println("TX is " + request.tx);
        System.out.println("Waiting for " + kit.peerGroup().getMaxConnections() + " connected peers");
        kit.peerGroup().addDisconnectedEventListener((peer, peerCount) -> System.out.println(peerCount +
                " peers connected"));
        kit.peerGroup().addConnectedEventListener((peer, peerCount) -> System.out.println(peerCount +
                " peers connected"));
        kit.peerGroup().broadcastTransaction(request.tx).future().get();
        System.out.println("Send complete, waiting for confirmation");
        request.tx.getConfidence().getDepthFuture(1).get();

        int heightNow = kit.chain().getBestChainHeight();
        System.out.println("Height after confirmation is " + heightNow);
        System.out.println("Result: took " + (heightNow - heightAtStart) + " blocks to confirm at this fee level");
    }
}
