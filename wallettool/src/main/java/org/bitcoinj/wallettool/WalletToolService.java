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
package org.bitcoinj.wallettool;

import com.google.protobuf.ByteString;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.base.internal.Preconditions;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.crypto.MnemonicException;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.KeyChainGroupStructure;
import org.bitcoinj.wallet.Protos;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletProtobufSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Implements the core functionality of the WalletTool. Manages the collection of wallet objects
 * and makes sure the state of each of them is properly managed.
 * Does not:
 * <ul>
 *     <li>Write to standard output or standard error</li>
 *     <li>Call System.exit</li>
 * </ul>
 * If a fatal error happens, it throws a {@link WalletToolException}. All output is returned as strings.
 * The {@link WalletTool} is responsible for:
 * <ul>
 *     <li>Parsing and validating arguments</li>
 *     <li>Displaying help</li>
 *     <li>Calling the correct methods in this class with the correct parameters</li>
 *     <li>Displaying command output and errors</li>
 *     <li>Calling System.exit</li>
 */
public class WalletToolService implements AutoCloseable {
    private static final Logger log = LoggerFactory.getLogger(WalletToolService.class);
    private final File walletFile;
    private final File chainFile;
    private Wallet wallet;
    private PeerGroup peerGroup;
    private BlockStore store;

    public WalletToolService(File walletFile, File chainFile) {
        this.walletFile = walletFile;
        this.chainFile = chainFile;
        Context.propagate(new Context());
    }

    // If chainfile not specified, will be same name as wallet, but with .chain extension?
    // This would be a change from previous behavior, but will be consistent with WalletAppKit
    public WalletToolService(File walletFile) {
        this(walletFile, new File("TBD") );
    }

    public void createNewWallet(Network network,
                              ScriptType outputScriptType,
                              String password,
                              boolean force) throws WalletToolException {
    }

    public void createFromSeeds(List<String> seedWords,
                                Network network,
                                ScriptType outputScriptType,
                                String password,
                                Instant creationTime,
                                boolean force) throws WalletToolException {
    }

    public void createFromWatchKey(String watchKeyStr,
                                Network network,
                                ScriptType outputScriptType,
                                String password,
                                Instant creationTime,
                                boolean force) throws WalletToolException {
    }

    public void loadFromFile(boolean forceReset, boolean ignoreMandatoryExtensions) {
        
    }

    public void dumpWallet() throws WalletToolException {}
    public void addKey() {}
    public void addAddr() {}
    public void deleteKey() {}
    public void currentReceiveAddr() {}
    public void reset() {}
    public void syncChain() {}
    public void send() {}
    public void encrypt() {}
    public void decrypt() {}
    public void upgrade() {}
    public void rotate() {}
    public void setCreationTime() {}

    public boolean isConsistent() {
        return wallet.isConsistent();
    }

    public void save() throws WalletToolException {
        try {
            // This will save the new state of the wallet to a temp file then rename, in case anything goes wrong.
            wallet.saveToFile(walletFile);
        } catch (IOException e) {
            throw new WalletToolException("Failed to save wallet! Old wallet should be left untouched.", e);
        }
    }

    public CompletableFuture<String> wait(WalletTool.WaitForEnum waitFor, WalletTool.Condition condition) {
        //setup();
        CompletableFuture<String> futureMessage = wait(waitFor, condition);
        if (!peerGroup.isRunning())
            peerGroup.startAsync();
        return futureMessage;
    }

    @Override
    public void close() throws WalletToolException {
        try {
            if (peerGroup == null) return;  // setup() never called so nothing to do.
            if (peerGroup.isRunning())
                peerGroup.stop();
            save();
            store.close();
            wallet = null;
        } catch (BlockStoreException e) {
            throw new WalletToolException("Exception while closing", e);
        }
    }

    public boolean networkMatches(Network network) {
        Objects.requireNonNull(wallet);
        return wallet.network() == network;
    }

    public String rawDump() throws IOException {
        // Just parse the protobuf as much as possible, then bail out. Don't try and do a real deserialization.
        // This is useful mostly for investigating corrupted wallets.
        try (FileInputStream stream = new FileInputStream(walletFile)) {
            Protos.Wallet proto = WalletProtobufSerializer.parseToProto(stream);
            return attemptHexConversion(proto).toString();
        }
    }

    /**
     * Wait for a condition to be satisfied
     * @param waitFor condition type to wait for
     * @param condition balance condition to wait for
     * @return A (future) human-readable message (txId, block hash, or balance) to display when wait is complete
     */
    private CompletableFuture<String> waitInternal(WalletTool.WaitForEnum waitFor, WalletTool.Condition condition) {
        CompletableFuture<String> future = new CompletableFuture<>();
        switch (waitFor) {
            case EVER:
                break;  // Future will never complete

            case WALLET_TX:
                // Future will complete with a transaction ID string
                Consumer<Transaction> txListener = tx ->  future.complete(tx.getTxId().toString());
                // Both listeners run in a peer thread
                wallet.addCoinsReceivedEventListener((wallet, tx, prevBalance, newBalance) -> txListener.accept(tx));
                wallet.addCoinsSentEventListener((wallet, tx, prevBalance, newBalance) -> txListener.accept(tx));
                break;

            case BLOCK:
                // Future will complete with a Block hash string
                peerGroup.addBlocksDownloadedEventListener((peer, block, filteredBlock, blocksLeft) ->
                        future.complete(block.getHashAsString())
                );
                break;

            case BALANCE:
                // Future will complete with a balance amount string
                // Check if the balance already meets the given condition.
                Coin existingBalance = wallet.getBalance(Wallet.BalanceType.ESTIMATED);
                if (condition.matchBitcoins(existingBalance)) {
                    future.complete(existingBalance.toFriendlyString());
                } else {
                    Runnable onChange = () -> {
                        synchronized (this) {
                            try {
                                save();
                            } catch (WalletToolException e) {
                                future.completeExceptionally(e);
                            }
                            Coin balance = wallet.getBalance(Wallet.BalanceType.ESTIMATED);
                            if (condition.matchBitcoins(balance)) {
                                future.complete(balance.toFriendlyString());
                            }
                        }
                    };
                    wallet.addCoinsReceivedEventListener((w, t, p, n) -> onChange.run());
                    wallet.addCoinsSentEventListener((w, t, p, n) -> onChange.run());
                    wallet.addChangeEventListener(w -> onChange.run());
                    wallet.addReorganizeEventListener(w -> onChange.run());
                }
                break;
        }
        return future;
    }


    private static Protos.Wallet attemptHexConversion(Protos.Wallet proto) {
        // Try to convert any raw hashes and such to textual equivalents for easier debugging. This makes it a bit
        // less "raw" but we will just abort on any errors.
        try {
            Protos.Wallet.Builder builder = proto.toBuilder();
            for (Protos.Transaction tx : builder.getTransactionList()) {
                Protos.Transaction.Builder txBuilder = tx.toBuilder();
                txBuilder.setHash(bytesToHex(txBuilder.getHash()));
                for (int i = 0; i < txBuilder.getBlockHashCount(); i++)
                    txBuilder.setBlockHash(i, bytesToHex(txBuilder.getBlockHash(i)));
                for (Protos.TransactionInput input : txBuilder.getTransactionInputList()) {
                    Protos.TransactionInput.Builder inputBuilder = input.toBuilder();
                    inputBuilder.setTransactionOutPointHash(bytesToHex(inputBuilder.getTransactionOutPointHash()));
                }
                for (Protos.TransactionOutput output : txBuilder.getTransactionOutputList()) {
                    Protos.TransactionOutput.Builder outputBuilder = output.toBuilder();
                    if (outputBuilder.hasSpentByTransactionHash())
                        outputBuilder.setSpentByTransactionHash(bytesToHex(outputBuilder.getSpentByTransactionHash()));
                }
                // TODO: keys, ip addresses etc.
            }
            return builder.build();
        } catch (Throwable throwable) {
            log.error("Failed to do hex conversion on wallet proto", throwable);
            return proto;
        }
    }

    private static ByteString bytesToHex(ByteString bytes) {
        return ByteString.copyFrom(ByteUtils.formatHex(bytes.toByteArray()).getBytes());
    }


    private static class WalletToolException extends Exception {
        public WalletToolException(String s, Exception e) {
            super(s, e);
        }
    }
}

