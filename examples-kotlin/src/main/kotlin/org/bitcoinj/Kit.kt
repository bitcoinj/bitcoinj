package org.bitcoinj

import org.bitcoinj.base.BitcoinNetwork
import org.bitcoinj.base.Coin
import org.bitcoinj.core.Transaction
import org.bitcoinj.crypto.ECKey
import org.bitcoinj.kits.WalletAppKit
import org.bitcoinj.script.Script
import org.bitcoinj.wallet.Wallet
import java.io.File


/**
 * The following example shows how to use the by bitcoinj provided WalletAppKit.
 * The WalletAppKit class wraps the boilerplate (Peers, BlockChain, BlockStorage, Wallet) needed to set up a new SPV bitcoinj app.
 *
 * In this example we also define a WalletEventListener class with implementors that are called when the wallet changes (for example sending/receiving money)
 */

fun main(args: Array<String>) {

    // First we configure the network we want to use.
    // The available options are:
    // - BitcoinNetwork.MAINNET
    // - BitcoinNetwork.TESTTEST
    // - BitcoinNetwork.SIGNET
    // - BitcoinNetwork.REGTEST
    // While developing your application you probably want to use the Regtest mode and run your local bitcoin network. Run bitcoind with the -regtest flag
    // To test you app with a real network you can use the testnet. The testnet is an alternative bitcoin network that follows the same rules as main network.
    // Coins are worth nothing and you can get coins from a faucet.
    //
    // For more information have a look at: https://bitcoinj.github.io/testing and https://bitcoin.org/en/developer-examples#testing-applications
    val network = BitcoinNetwork.TESTNET

    // Initialize and start a WalletAppKit. The kit handles all the boilerplate for us and is the easiest way to get everything up and running.
    // Look at the WalletAppKit documentation and its source to understand what's happening behind the scenes: https://github.com/bitcoinj/bitcoinj/blob/master/core/src/main/java/org/bitcoinj/kits/WalletAppKit.java
    // WalletAppKit extends the Guava AbstractIdleService. Have a look at the introduction to Guava services: https://github.com/google/guava/wiki/ServiceExplained
    val kit = WalletAppKit.launch(network, File("."), "walletappkit-example") { k: WalletAppKit? ->
        // In case you want to connect with your local bitcoind tell the kit to connect to localhost.
        // This is done automatically in reg test mode.
        // k.connectToLocalHost();
    }
    kit.wallet()
        .addCoinsReceivedEventListener { wallet: Wallet?, tx: Transaction, prevBalance: Coin?, newBalance: Coin? ->
            println("-----> coins received: " + tx.txId)
            println("received: " + tx.getValue(wallet))
        }

    kit.wallet()
        .addCoinsSentEventListener { wallet: Wallet?, tx: Transaction?, prevBalance: Coin?, newBalance: Coin? -> println("coins sent") }

    kit.wallet().addKeyChainEventListener { keys: List<ECKey?>? -> println("new key added") }

    kit.wallet().addScriptsChangeEventListener { wallet: Wallet?, scripts: List<Script?>?, isAddingScripts: Boolean -> println("new script added") }

    kit.wallet().addTransactionConfidenceEventListener { wallet: Wallet?, tx: Transaction ->
        println("-----> confidence changed: " + tx.txId)
        val confidence = tx.confidence
        println("new block depth: " + confidence.depthInBlocks)
    }

    // Ready to run. The kit syncs the blockchain and our wallet event listener gets notified when something happens.
    // To test everything we create and print a fresh receiving address. Send some coins to that address and see if everything works.
    println("send money to: " + kit.wallet().freshReceiveAddress().toString())

    // Make sure to properly shut down all the running services when you manually want to stop the kit. The WalletAppKit registers a runtime ShutdownHook so we actually do not need to worry about that when our application is stopping.
    //System.out.println("shutting down again");
    //kit.stopAsync();
    //kit.awaitTerminated();
}
