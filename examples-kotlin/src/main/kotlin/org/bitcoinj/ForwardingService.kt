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

import org.bitcoinj.base.*
import org.bitcoinj.core.*
import org.bitcoinj.kits.WalletAppKit
import org.bitcoinj.utils.BriefLogFormatter
import org.bitcoinj.wallet.CoinSelector
import org.bitcoinj.wallet.SendRequest
import org.bitcoinj.wallet.Wallet
import org.bitcoinj.wallet.listeners.WalletCoinsReceivedEventListener
import java.io.Closeable
import java.io.File
import java.util.Objects.*
import java.util.concurrent.CompletableFuture

data class Config(
    val network: BitcoinNetwork,              // Network to operate on
    val forwardingAddress: Address,           // Address to forward to
    val walletDirectory: File,                // Directory to create wallet files in
    val walletPrefix: String,                 // Prefix for wallet file names
    val requiredConfirmations: Int,           // Required number of tx confirmations before forwarding
    val maxConnections: Int                   // Maximum number of connections
)

fun main(args: Array<String>) { //pass the network and forwarding address in this order [address, network]
    // This line makes the log output more compact and easily read, especially when using the JDK log adapter.
    BriefLogFormatter.init()
    Context.propagate(Context())

    val addressAndNetwork = parseArgs(args)
    val network: BitcoinNetwork = addressAndNetwork[1] as BitcoinNetwork
    val forwardingAddress: Address = addressAndNetwork[0] as Address

    val config = Config(network, forwardingAddress, File("."), getPrefix(network), 1, 4)

    println("Network: ${config.network}");
    println("Forwarding address: ${config.forwardingAddress}");

    // Create and start the WalletKit
    val walletAppKit: WalletAppKit =
        WalletAppKit.launch(network, config.walletDirectory, getPrefix(network), config.maxConnections)
    val forwardingService = ForwardingService(config, walletAppKit.wallet())

    walletAppKit.use { walletAppKit ->
        forwardingService.use { forwardingService ->
            // After we start listening, we can tell the user the receiving address
            println("Waiting to receive coins on: ${walletAppKit.wallet().currentReceiveAddress()}")
            println("Press Ctrl-C to quit.")

            // Wait for Control-C
            try {
                Thread.sleep(Long.MAX_VALUE)
            } catch (ignored: InterruptedException) {
            }
        }
    }
}

/**
 * ForwardingService demonstrates basic usage of bitcoinj. It creates an SPV Wallet, listens on the network
 * and when it receives coins, simply sends them onwards to the address given on the command line.
 */
class ForwardingService(val config: Config, val wallet: Wallet) : Closeable {

    /**
     * Start the wallet and register the coin-forwarding listener.
     */
    init {
        wallet.addCoinsReceivedEventListener(this::coinForwardingListener);
    }

    /**
     * A listener to receive coins and forward them to the configured address.
     * Implements the [WalletCoinsReceivedEventListener] functional interface.
     * @param wallet The active wallet
     * @param incomingTx the received transaction
     * @param prevBalance wallet balance before this transaction (unused)
     * @param newBalance wallet balance after this transaction (unused)
     */
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
                forward(wallet, incomingTx, config.forwardingAddress)
            }
            .whenComplete { broadcast: TransactionBroadcast?, throwable: Throwable ->
                if (broadcast != null) {
                    println("Sent ${broadcast.transaction().outputSum.toFriendlyString()} onwards and acknowledged by peers, via transaction ${broadcast.transaction().txId}\n")
                } else {
                    println("Exception occurred: $throwable")
                }
            }
    }

    /**
     * Forward an incoming transaction by creating a new transaction, signing, and sending to the specified address.
     * @param wallet The active wallet
     * @param incomingTx the received transaction
     * @param forwardingAddress the address to send to
     * @return A future for a TransactionBroadcast object that completes when relay is acknowledged by peers
     */
    fun forward(
        wallet: Wallet,
        incomingTx: Transaction,
        forwardingAddress: Address?
    ): CompletableFuture<TransactionBroadcast?> {
        // Send coins received in incomingTx onwards by sending exactly the outputs that have been sent to us
        val sendRequest = SendRequest.emptyWallet(forwardingAddress)
        sendRequest.coinSelector = forwardingCoinSelector(incomingTx.txId)
        println("Creating outgoing transaction for $forwardingAddress...\n")
        return wallet.sendTransaction(sendRequest)
            .thenCompose { broadcast: TransactionBroadcast ->
                println("Transaction ${broadcast.transaction().txId} is signed and is being delivered to ${wallet.network()}...\n")
                broadcast.awaitRelayed() // Wait until peers report they have seen the transaction
            }
    }

    /**
     * Create a CoinSelector that only returns outputs from a given parent transaction.
     *
     *
     * This is using the idea of partial function application to create a 2-argument function for coin selection
     * with a third, fixed argument of the transaction id.
     * @param parentTxId The parent transaction hash
     * @return a coin selector
     */
    fun forwardingCoinSelector(parentTxId: Sha256Hash): CoinSelector {
        requireNonNull(parentTxId)
        return CoinSelector.fromPredicate { output: TransactionOutput ->
            output.parentTransactionHash == parentTxId
        }
    }

    /**
     * Close the service.
     */
    override fun close() {
        wallet.removeCoinsReceivedEventListener(::coinForwardingListener)
    }
}

fun getPrefix(network: BitcoinNetwork?): String {
    return String.format("forwarding-service-%s", network.toString())
}

fun parseArgs(args: Array<String>): Array<Any> {
    val USAGE = "Usage: address-to-forward-to [mainnet|testnet|signet|regtest]"
    if (args.size < 1 || args.size > 2) {
        System.err.println(USAGE)
        System.exit(1)
    }
    val network: BitcoinNetwork
    val forwardingAddress: Address
    if (args.size >= 2) {
        // If network was specified, validate address against network
        network = BitcoinNetwork.fromString(args[1]).orElseThrow()
        forwardingAddress = AddressParser.getDefault(network).parseAddress(args[0])
    } else {
        // Else network not-specified, extract network from address
        forwardingAddress = AddressParser.getDefault().parseAddress(args[0])
        network = forwardingAddress.network() as BitcoinNetwork
    }
    return arrayOf(forwardingAddress, network)
}
