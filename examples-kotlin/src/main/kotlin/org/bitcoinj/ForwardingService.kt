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

import org.bitcoinj.base.Address
import org.bitcoinj.base.AddressParser
import org.bitcoinj.base.BitcoinNetwork
import org.bitcoinj.base.Coin
import org.bitcoinj.core.Context
import org.bitcoinj.core.Transaction
import org.bitcoinj.core.TransactionBroadcast
import org.bitcoinj.core.TransactionConfidence
import org.bitcoinj.kits.WalletAppKit
import org.bitcoinj.utils.BriefLogFormatter
import org.bitcoinj.wallet.CoinSelector
import org.bitcoinj.wallet.SendRequest
import org.bitcoinj.wallet.Wallet
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener
import java.io.Closeable
import java.io.File
import java.util.Objects
import java.util.concurrent.CompletableFuture


val NETS = BitcoinNetwork.strings().joinToString(separator = "|")
val USAGE = "Usage: address-to-forward-to $NETS"
fun main(args: Array<String>) { //pass the network and forwarding address in this order [address, network]
    // This line makes the log output more compact and easily read, especially when using the JDK log adapter.
    BriefLogFormatter.init()
    Context.propagate(Context())

    if (args.isEmpty() || args.size > 2) {
        System.err.println(USAGE)
        System.exit(1)
    }

    // If only an address is provided, derive network from the address
    // If address and network provided, use network and validate address against network
    val forwardingAddress: Address = AddressParser.getDefault().parseAddress(args[0])
    val config = if (args.size == 1) Config(forwardingAddress) else
        Config(forwardingAddress, BitcoinNetwork.fromString(args[1]).orElseThrow())
    println("Network: ${config.network}")
    println("Forwarding address: ${config.forwardingAddress}")

    // Create the service, which will listen for transactions and forward coins until closed
    ForwardingService(config).use { forwardingService ->
        // After we start listening, we can tell the user the receiving address
        println(forwardingService.status())
        println("Press Ctrl-C to quit.")

        // Wait for Control-C
        Thread.sleep(Long.MAX_VALUE)
    }
}

/**
 * ForwardingService demonstrates basic usage of bitcoinj. It creates an SPV Wallet, listens on the network
 * and when it receives coins, simply sends them onwards to the address given on the command line.
 */
class ForwardingService(val config: Config) : Closeable {
    val walletAppKit: WalletAppKit
    val wallet: Wallet

    /**
     * Start the wallet and register the coin-forwarding listener.
     */
    init {
        walletAppKit =
            WalletAppKit.launch(config.network, config.walletDirectory, config.walletPrefix, config.maxConnections)
        wallet = walletAppKit.wallet()
        wallet.addCoinsReceivedEventListener(this::coinForwardingListener)
    }

    /**
     * A listener to receive coins and forward them to the configured address.
     * Implements the [WalletCoinsReceivedEventListener] functional interface.
     * @param wallet The active wallet
     * @param incomingTx the received transaction
     * @param prevBalance wallet balance before this transaction (unused)
     * @param newBalance wallet balance after this transaction (unused)
     */
    @Suppress("UNUSED_PARAMETER")
    private fun coinForwardingListener(wallet: Wallet, incomingTx: Transaction, prevBalance: Coin, newBalance: Coin) {
        // Incoming transaction received, now "compose" (i.e. chain) a call to wait for required confirmations
        // The transaction "incomingTx" can either be pending, or included into a block (we didn't see the broadcast).
        val value = incomingTx.getValueSentToMe(wallet)
        println("Received tx for ${value.toFriendlyString()} : $incomingTx \n")
        println("Transaction will be forwarded after it confirms.")
        println("Waiting for confirmation...")
        wallet.waitForConfirmations(incomingTx, config.requiredConfirmations)
            .thenCompose { confidence: TransactionConfidence ->
                // Required confirmations received, now create and send forwarding transaction
                println("Incoming tx has received ${confidence.depthInBlocks} confirmations.\n")
                // Send coins received in incomingTx onwards by sending exactly the UTXOs we have just received.
                // We're not truly emptying the wallet because we're limiting the available outputs with a CoinSelector.
                println("Creating outgoing transaction for ${config.forwardingAddress}...\n");
                val sendRequest = SendRequest.emptyWallet(config.forwardingAddress)
                // Use a CoinSelector that only returns wallet UTXOs from the incoming transaction.
                sendRequest.coinSelector = CoinSelector.fromPredicate { output ->
                    Objects.equals(
                        output.parentTransactionHash,
                        incomingTx.txId
                    )
                }
                send(wallet, sendRequest)
            }
            .whenComplete { broadcast: TransactionBroadcast?, throwable: Throwable? ->
                if (broadcast != null) {
                    println("Sent ${broadcast.transaction().outputSum.toFriendlyString()} onwards and acknowledged by peers, via transaction ${broadcast.transaction().txId}\n")
                } else {
                    println("Exception occurred: $throwable")
                }
            }
    }

    /**
     * Create a transaction specified by a {@link org.bitcoinj.examples.SendRequest}, sign it, and send to the specified address.
     * @param wallet The active wallet
     * @param sendRequest requested transaction parameters
     * @return A future for a TransactionBroadcast object that completes when relay is acknowledged by peers
     */
    fun send(wallet: Wallet, sendRequest: SendRequest?): CompletableFuture<TransactionBroadcast?>? {
        return wallet.sendTransaction(sendRequest)
            .thenCompose { broadcast: TransactionBroadcast ->
                println("Transaction ${broadcast.transaction().txId} is signed and is being delivered to ${wallet.network()}...\n")
                broadcast.awaitRelayed() // Wait until peers report they have seen the transaction
            }
            .whenComplete { broadcast: TransactionBroadcast?, throwable: Throwable? ->
                if (broadcast != null) {
                    println("Sent ${broadcast.transaction().outputSum.toFriendlyString()} onwards and acknowledged by peers, via transaction ${broadcast.transaction().txId}\n")
                } else {
                    println("Exception occurred: $throwable")
                }
            }
    }

    fun status(): String? {
        return String.format("Waiting to receive coins on: %s", wallet.currentReceiveAddress())
    }

    /**
     * Close the service.
     */
    override fun close() {
        wallet.removeCoinsReceivedEventListener(::coinForwardingListener)
        walletAppKit.close()
    }
}

data class Config(
    val forwardingAddress: Address,                                              // Address to forward to
    val network: BitcoinNetwork,                                                 // Network to operate on
    val walletDirectory: File,                                                   // Directory to create wallet files in
    val walletPrefix: String = getPrefix(network),                               // Prefix for wallet file names
    val requiredConfirmations: Int = 1,                                          // Required number of tx confirmations before forwarding
    val maxConnections: Int = 4                                                  // Maximum number of connections
) {
    constructor(forwardingAddress: Address) : this(
        forwardingAddress,
        forwardingAddress.network() as BitcoinNetwork
    )

    constructor(forwardingAddress: Address, network: BitcoinNetwork) : this(
        network.checkAddress(forwardingAddress),
        network,
        File(".")
    )

    companion object {
        fun getPrefix(network: BitcoinNetwork): String {
            return String.format("forwarding-service-%s", network.toString())
        }
    }
}
