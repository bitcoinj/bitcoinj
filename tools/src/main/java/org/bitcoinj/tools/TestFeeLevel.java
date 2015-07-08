package org.bitcoinj.tools;

import org.bitcoinj.core.*;
import org.bitcoinj.kits.WalletAppKit;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.utils.BriefLogFormatter;

import java.io.File;

/**
 * A program that sends a transaction with the specified fee and measures how long it takes to confirm.
 */
public class TestFeeLevel {

    public static final MainNetParams PARAMS = MainNetParams.get();
    private static WalletAppKit kit;

    public static void main(String[] args) throws Exception {
        BriefLogFormatter.initWithSilentBitcoinJ();
        if (args.length == 0) {
            System.err.println("Specify the fee level to test in satoshis as the first argument.");
            return;
        }

        Coin feeToTest = Coin.valueOf(Long.parseLong(args[0]));
        System.out.println("Fee to test is " + feeToTest.toFriendlyString());

        kit = new WalletAppKit(PARAMS, new File("."), "testfeelevel");
        kit.startAsync();
        kit.awaitRunning();
        try {
            go(feeToTest);
        } finally {
            kit.stopAsync();
            kit.awaitTerminated();
        }
    }

    private static void go(Coin feeToTest) throws InterruptedException, java.util.concurrent.ExecutionException, InsufficientMoneyException {
        kit.peerGroup().setMaxConnections(50);

        if (kit.wallet().getBalance().compareTo(feeToTest) < 0) {
            System.out.println("Send some money to " + kit.wallet().currentReceiveAddress());
            System.out.println("... and wait for it to confirm");
            kit.wallet().getBalanceFuture(feeToTest, Wallet.BalanceType.AVAILABLE).get();
        }

        int heightAtStart = kit.chain().getBestChainHeight();
        System.out.println("Height at start is " + heightAtStart);

        Coin value = kit.wallet().getBalance().subtract(feeToTest);
        Coin halfValue = value.divide(2);
        Transaction transaction = new Transaction(PARAMS);
        transaction.addOutput(halfValue, kit.wallet().freshReceiveAddress());
        transaction.addOutput(value.subtract(halfValue), kit.wallet().freshReceiveAddress());
        Wallet.SendRequest request = Wallet.SendRequest.forTx(transaction);
        request.feePerKb = feeToTest;
        request.ensureMinRequiredFee = false;
        kit.wallet().completeTx(request);
        System.out.println("Size in bytes is " + request.tx.bitcoinSerialize().length);
        System.out.println("TX is " + request.tx);
        kit.peerGroup().broadcastTransaction(request.tx).future().get();
        System.out.println("Send complete, waiting for confirmation");
        request.tx.getConfidence().getDepthFuture(1).get();

        int heightNow = kit.chain().getBestChainHeight();
        System.out.println("Height after confirmation is " + heightNow);
        System.out.println("Result: took " + (heightNow - heightAtStart) + " blocks to confirm at this fee level");
    }
}
