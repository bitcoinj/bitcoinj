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

package org.bitcoinj.kits;

import com.google.common.io.Closeables;
import com.google.common.util.concurrent.AbstractIdleService;
import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.BlockChain;
import org.bitcoinj.core.CheckpointManager;
import org.bitcoinj.core.Context;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.PeerAddress;
import org.bitcoinj.core.PeerGroup;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.listeners.DownloadProgressTracker;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.net.discovery.DnsDiscovery;
import org.bitcoinj.net.discovery.PeerDiscovery;
import org.bitcoinj.store.BlockStore;
import org.bitcoinj.store.BlockStoreException;
import org.bitcoinj.store.SPVBlockStore;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.KeyChainGroup;
import org.bitcoinj.wallet.KeyChainGroupStructure;
import org.bitcoinj.wallet.Wallet;
import org.bitcoinj.wallet.WalletExtension;
import org.bitcoinj.wallet.WalletProtobufSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.channels.FileLock;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * <p>Utility class that wraps the boilerplate needed to set up a new SPV bitcoinj app. Instantiate it with a directory
 * and file prefix, optionally configure a few things, then use startAsync and optionally awaitRunning. The object will
 * construct and configure a {@link BlockChain}, {@link SPVBlockStore}, {@link Wallet} and {@link PeerGroup}. Depending
 * on the value of the blockingStartup property, startup will be considered complete once the block chain has fully
 * synchronized, so it can take a while.</p>
 *
 * <p>To add listeners and modify the objects that are constructed, you can either do that by overriding the
 * {@link #onSetupCompleted()} method (which will run on a background thread) and make your changes there,
 * or by waiting for the service to start and then accessing the objects from wherever you want. However, you cannot
 * access the objects this class creates until startup is complete.</p>
 *
 * <p>The asynchronous design of this class may seem puzzling (just use {@link #awaitRunning()} if you don't want that).
 * It is to make it easier to fit bitcoinj into GUI apps, which require a high degree of responsiveness on their main
 * thread which handles all the animation and user interaction. Even when blockingStart is false, initializing bitcoinj
 * means doing potentially blocking file IO, generating keys and other potentially intensive operations. By running it
 * on a background thread, there's no risk of accidentally causing UI lag.</p>
 *
 * <p>Note that {@link #awaitRunning()} can throw an unchecked {@link IllegalStateException}
 * if anything goes wrong during startup - you should probably handle it and use {@link Exception#getCause()} to figure
 * out what went wrong more precisely. Same thing if you just use the {@link #startAsync()} method.</p>
 */
public class WalletAppKit extends AbstractIdleService {
    protected static final Logger log = LoggerFactory.getLogger(WalletAppKit.class);

    protected final BitcoinNetwork network;
    protected final NetworkParameters params;
    protected final ScriptType preferredOutputScriptType;
    protected final KeyChainGroupStructure structure;
    protected final String filePrefix;
    protected volatile BlockChain vChain;
    protected volatile SPVBlockStore vStore;
    protected volatile Wallet vWallet;
    protected volatile PeerGroup vPeerGroup;

    protected final File directory;
    protected volatile File vWalletFile;

    protected boolean useAutoSave = true;
    protected PeerAddress[] peerAddresses;
    protected DownloadProgressTracker downloadListener;
    protected boolean autoStop = true;
    protected InputStream checkpoints;
    protected boolean blockingStartup = true;
    protected String userAgent, version;
    @Nonnull protected WalletProtobufSerializer.WalletFactory walletFactory = WalletProtobufSerializer.WalletFactory.DEFAULT;
    @Nullable protected DeterministicSeed restoreFromSeed;
    @Nullable protected DeterministicKey restoreFromKey;
    @Nullable protected PeerDiscovery discovery;

    /**
     * Creates a new WalletAppKit, with a newly created {@link Context}. Files will be stored in the given directory.
     * @deprecated Use {@link #WalletAppKit(BitcoinNetwork, ScriptType, KeyChainGroupStructure, File, String)}
     */
    @Deprecated
    public WalletAppKit(NetworkParameters params, File directory, String filePrefix) {
        this(params.network(), ScriptType.P2PKH, KeyChainGroupStructure.BIP32, directory, filePrefix);
    }

    /**
     * Creates a new WalletAppKit, with a newly created {@link Context}. Files will be stored in the given directory.
     * @deprecated Use {@link #WalletAppKit(BitcoinNetwork, ScriptType, KeyChainGroupStructure, File, String)}
     */
    @Deprecated
    public WalletAppKit(NetworkParameters params, ScriptType preferredOutputScriptType,
            @Nullable KeyChainGroupStructure structure, File directory, String filePrefix) {
        this(params.network(), preferredOutputScriptType, structure, directory, filePrefix);
    }

    /**
     * Creates a new WalletAppKit, on the specified {@link BitcoinNetwork}. Files will be stored in the given directory.
     *
     * @param network The network the wallet connects to
     * @param preferredOutputScriptType The output script type (and therefore {@code Address} type) of the wallet
     * @param structure The keychain group structure (e.g. {@link KeyChainGroupStructure#BIP43} or {@link KeyChainGroupStructure#BIP32}
     * @param directory The directory for creating {@code .wallet} and {@code .spvchain} files
     * @param filePrefix The base name for the {@code .wallet} and {@code .spvchain} files
     */
    public WalletAppKit(BitcoinNetwork network, ScriptType preferredOutputScriptType,
                        KeyChainGroupStructure structure, File directory, String filePrefix) {
        this.network = checkNotNull(network);
        this.params = NetworkParameters.of(this.network);
        this.preferredOutputScriptType = checkNotNull(preferredOutputScriptType);
        this.structure = checkNotNull(structure);
        this.directory = checkNotNull(directory);
        this.filePrefix = checkNotNull(filePrefix);
    }

    /** Will only connect to the given addresses. Cannot be called after startup. */
    public WalletAppKit setPeerNodes(PeerAddress... addresses) {
        checkState(state() == State.NEW, "Cannot call after startup");
        this.peerAddresses = addresses;
        return this;
    }

    /** Will only connect to localhost. Cannot be called after startup. */
    public WalletAppKit connectToLocalHost() {
        try {
            final InetAddress localHost = InetAddress.getLocalHost();
            return setPeerNodes(new PeerAddress(params, localHost, params.getPort()));
        } catch (UnknownHostException e) {
            // Borked machine with no loopback adapter configured properly.
            throw new RuntimeException(e);
        }
    }

    /** If true, the wallet will save itself to disk automatically whenever it changes. */
    public WalletAppKit setAutoSave(boolean value) {
        checkState(state() == State.NEW, "Cannot call after startup");
        useAutoSave = value;
        return this;
    }

    /**
     * If you want to learn about the sync process, you can provide a listener here. For instance, a
     * {@link DownloadProgressTracker} is a good choice. This has no effect unless setBlockingStartup(false) has been called
     * too, due to some missing implementation code.
     */
    public WalletAppKit setDownloadListener(DownloadProgressTracker listener) {
        this.downloadListener = listener;
        return this;
    }

    /** If true, will register a shutdown hook to stop the library. Defaults to true. */
    public WalletAppKit setAutoStop(boolean autoStop) {
        this.autoStop = autoStop;
        return this;
    }

    /**
     * If set, the file is expected to contain a checkpoints file calculated with BuildCheckpoints. It makes initial
     * block sync faster for new users - please refer to the documentation on the bitcoinj website
     * (https://bitcoinj.github.io/speeding-up-chain-sync) for further details.
     */
    public WalletAppKit setCheckpoints(InputStream checkpoints) {
        if (this.checkpoints != null)
            Closeables.closeQuietly(checkpoints);
        this.checkpoints = checkNotNull(checkpoints);
        return this;
    }

    /**
     * If true (the default) then the startup of this service won't be considered complete until the network has been
     * brought up, peer connections established and the block chain synchronised. Therefore {@link #awaitRunning()} can
     * potentially take a very long time. If false, then startup is considered complete once the network activity
     * begins and peer connections/block chain sync will continue in the background.
     */
    public WalletAppKit setBlockingStartup(boolean blockingStartup) {
        this.blockingStartup = blockingStartup;
        return this;
    }

    /**
     * Sets the string that will appear in the subver field of the version message.
     * @param userAgent A short string that should be the name of your app, e.g. "My Wallet"
     * @param version A short string that contains the version number, e.g. "1.0-BETA"
     */
    public WalletAppKit setUserAgent(String userAgent, String version) {
        this.userAgent = checkNotNull(userAgent);
        this.version = checkNotNull(version);
        return this;
    }

    /**
     * Sets a wallet factory which will be used when the kit creates a new wallet.
     * @param walletFactory Factory for making new wallets (Use {@link WalletProtobufSerializer.WalletFactory#DEFAULT} for default behavior)
     * @return WalletAppKit for method chaining purposes
     */
    public WalletAppKit setWalletFactory(@Nonnull WalletProtobufSerializer.WalletFactory walletFactory) {
        checkNotNull(walletFactory);
        this.walletFactory = walletFactory;
        return this;
    }

    /**
     * If a seed is set here then any existing wallet that matches the file name will be renamed to a backup name,
     * the chain file will be deleted, and the wallet object will be instantiated with the given seed instead of
     * a fresh one being created. This is intended for restoring a wallet from the original seed. To implement restore
     * you would shut down the existing appkit, if any, then recreate it with the seed given by the user, then start
     * up the new kit. The next time your app starts it should work as normal (that is, don't keep calling this each
     * time).
     */
    public WalletAppKit restoreWalletFromSeed(DeterministicSeed seed) {
        this.restoreFromSeed = seed;
        return this;
    }

    /**
     * If an account key is set here then any existing wallet that matches the file name will be renamed to a backup name,
     * the chain file will be deleted, and the wallet object will be instantiated with the given key instead of
     * a fresh seed being created. This is intended for restoring a wallet from an account key. To implement restore
     * you would shut down the existing appkit, if any, then recreate it with the key given by the user, then start
     * up the new kit. The next time your app starts it should work as normal (that is, don't keep calling this each
     * time).
     */
    public WalletAppKit restoreWalletFromKey(DeterministicKey accountKey) {
        this.restoreFromKey = accountKey;
        return this;
    }

    /**
     * Sets the peer discovery class to use. If none is provided then DNS is used, which is a reasonable default.
     */
    public WalletAppKit setDiscovery(@Nullable PeerDiscovery discovery) {
        this.discovery = discovery;
        return this;
    }

    /**
     * <p>Override this to return wallet extensions if any are necessary.</p>
     *
     * <p>When this is called, chain(), store(), and peerGroup() will return the created objects, however they are not
     * initialized/started.</p>
     */
    protected List<WalletExtension> provideWalletExtensions() throws Exception {
        return Collections.emptyList();
    }

    /**
     * This method is invoked on a background thread after all objects are initialised, but before the peer group
     * or block chain download is started. You can tweak the objects configuration here.
     */
    protected void onSetupCompleted() { }

    /**
     * Tests to see if the spvchain file has an operating system file lock on it. Useful for checking if your app
     * is already running. If another copy of your app is running and you start the appkit anyway, an exception will
     * be thrown during the startup process. Returns false if the chain file does not exist or is a directory.
     */
    public boolean isChainFileLocked() throws IOException {
        RandomAccessFile file2 = null;
        try {
            File file = new File(directory, filePrefix + ".spvchain");
            if (!file.exists())
                return false;
            if (file.isDirectory())
                return false;
            file2 = new RandomAccessFile(file, "rw");
            FileLock lock = file2.getChannel().tryLock();
            if (lock == null)
                return true;
            lock.release();
            return false;
        } finally {
            if (file2 != null)
                file2.close();
        }
    }

    @Override
    protected void startUp() throws Exception {
        // Runs in a separate thread.
        if (!directory.exists()) {
            if (!directory.mkdirs()) {
                throw new IOException("Could not create directory " + directory.getAbsolutePath());
            }
        }
        log.info("Starting up with directory = {}", directory);
        try {
            File chainFile = new File(directory, filePrefix + ".spvchain");
            boolean chainFileExists = chainFile.exists();
            vWalletFile = new File(directory, filePrefix + ".wallet");
            boolean shouldReplayWallet = (vWalletFile.exists() && !chainFileExists) || restoreFromSeed != null || restoreFromKey != null;
            vWallet = createOrLoadWallet(shouldReplayWallet);

            // Initiate Bitcoin network objects (block store, blockchain and peer group)
            vStore = new SPVBlockStore(params, chainFile);
            if (!chainFileExists || restoreFromSeed != null || restoreFromKey != null) {
                if (checkpoints == null && !Utils.isAndroidRuntime()) {
                    checkpoints = CheckpointManager.openStream(params);
                }

                if (checkpoints != null) {
                    // Initialize the chain file with a checkpoint to speed up first-run sync.
                    long time;
                    if (restoreFromSeed != null) {
                        time = restoreFromSeed.getCreationTimeSeconds();
                        if (chainFileExists) {
                            log.info("Clearing the chain file in preparation for restore.");
                            vStore.clear();
                        }
                    } else if (restoreFromKey != null) {
                        time = restoreFromKey.getCreationTimeSeconds();
                        if (chainFileExists) {
                            log.info("Clearing the chain file in preparation for restore.");
                            vStore.clear();
                        }
                    }
                    else
                    {
                        time = vWallet.getEarliestKeyCreationTime();
                    }
                    if (time > 0)
                        CheckpointManager.checkpoint(params, checkpoints, vStore, time);
                    else
                        log.warn("Creating a new uncheckpointed block store due to a wallet with a creation time of zero: this will result in a very slow chain sync");
                } else if (chainFileExists) {
                    log.info("Clearing the chain file in preparation for restore.");
                    vStore.clear();
                }
            }
            vChain = new BlockChain(params, vStore);
            vPeerGroup = createPeerGroup();
            if (this.userAgent != null)
                vPeerGroup.setUserAgent(userAgent, version);

            // Set up peer addresses or discovery first, so if wallet extensions try to broadcast a transaction
            // before we're actually connected the broadcast waits for an appropriate number of connections.
            if (peerAddresses != null) {
                for (PeerAddress addr : peerAddresses) vPeerGroup.addAddress(addr);
                vPeerGroup.setMaxConnections(peerAddresses.length);
                peerAddresses = null;
            } else if (!params.getId().equals(BitcoinNetwork.ID_REGTEST)) {
                vPeerGroup.addPeerDiscovery(discovery != null ? discovery : new DnsDiscovery(params));
            }
            vChain.addWallet(vWallet);
            vPeerGroup.addWallet(vWallet);
            onSetupCompleted();

            if (blockingStartup) {
                vPeerGroup.start();
                // Make sure we shut down cleanly.
                installShutdownHook();

                // TODO: Be able to use the provided download listener when doing a blocking startup.
                final DownloadProgressTracker listener = new DownloadProgressTracker();
                vPeerGroup.startBlockChainDownload(listener);
                listener.await();
            } else {
                vPeerGroup.startAsync().whenComplete((result, t) -> {
                    if (t == null) {
                        final DownloadProgressTracker l = downloadListener == null ? new DownloadProgressTracker() : downloadListener;
                        vPeerGroup.startBlockChainDownload(l);
                    } else {
                        throw new RuntimeException(t);
                    }
                });
            }
        } catch (BlockStoreException e) {
            throw new IOException(e);
        }
    }

    private Wallet createOrLoadWallet(boolean shouldReplayWallet) throws Exception {
        Wallet wallet;

        maybeMoveOldWalletOutOfTheWay();

        if (vWalletFile.exists()) {
            wallet = loadWallet(shouldReplayWallet);
        } else {
            wallet = createWallet();
            wallet.freshReceiveKey();
            for (WalletExtension e : provideWalletExtensions()) {
                wallet.addExtension(e);
            }

            // Currently the only way we can be sure that an extension is aware of its containing wallet is by
            // deserializing the extension (see WalletExtension#deserializeWalletExtension(Wallet, byte[]))
            // Hence, we first save and then load wallet to ensure any extensions are correctly initialized.
            wallet.saveToFile(vWalletFile);
            wallet = loadWallet(false);
        }

        if (useAutoSave) {
            this.setupAutoSave(wallet);
        }

        return wallet;
    }

    protected void setupAutoSave(Wallet wallet) {
        wallet.autosaveToFile(vWalletFile, 5, TimeUnit.SECONDS, null);
    }

    private Wallet loadWallet(boolean shouldReplayWallet) throws Exception {
        WalletExtension[] extensions = provideWalletExtensions().toArray(new WalletExtension[0]);
        return Wallet.loadFromFile(vWalletFile, walletFactory, shouldReplayWallet, false, extensions );
    }

    protected Wallet createWallet() {
        KeyChainGroup.Builder kcg = KeyChainGroup.builder(params, structure);
        if (restoreFromSeed != null)
            kcg.fromSeed(restoreFromSeed, preferredOutputScriptType);
        else if (restoreFromKey != null)
            kcg.fromKey(restoreFromKey, preferredOutputScriptType).build();
        else
            kcg.fromRandom(preferredOutputScriptType);

        return walletFactory.create(params, kcg.build());
    }

    private void maybeMoveOldWalletOutOfTheWay() {
        if (restoreFromSeed == null && restoreFromKey == null) return;
        if (!vWalletFile.exists()) return;
        int counter = 1;
        File newName;
        do {
            newName = new File(vWalletFile.getParent(), "Backup " + counter + " for " + vWalletFile.getName());
            counter++;
        } while (newName.exists());
        log.info("Renaming old wallet file {} to {}", vWalletFile, newName);
        if (!vWalletFile.renameTo(newName)) {
            // This should not happen unless something is really messed up.
            throw new RuntimeException("Failed to rename wallet for restore");
        }
    }

    protected PeerGroup createPeerGroup() {
        return new PeerGroup(params, vChain);
    }

    private void installShutdownHook() {
        if (autoStop) Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try {
                WalletAppKit.this.stopAsync();
                WalletAppKit.this.awaitTerminated();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }));
    }

    @Override
    protected void shutDown() throws Exception {
        // Runs in a separate thread.
        try {
            vPeerGroup.stop();
            vWallet.saveToFile(vWalletFile);
            vStore.close();

            vPeerGroup = null;
            vWallet = null;
            vStore = null;
            vChain = null;
        } catch (BlockStoreException e) {
            throw new IOException(e);
        }
    }

    public BitcoinNetwork network() {
        return network;
    }

    public NetworkParameters params() {
        return params;
    }

    public BlockChain chain() {
        checkState(state() == State.STARTING || state() == State.RUNNING, "Cannot call until startup is complete");
        return vChain;
    }

    public BlockStore store() {
        checkState(state() == State.STARTING || state() == State.RUNNING, "Cannot call until startup is complete");
        return vStore;
    }

    public Wallet wallet() {
        checkState(state() == State.STARTING || state() == State.RUNNING, "Cannot call until startup is complete");
        return vWallet;
    }

    public PeerGroup peerGroup() {
        checkState(state() == State.STARTING || state() == State.RUNNING, "Cannot call until startup is complete");
        return vPeerGroup;
    }

    public File directory() {
        return directory;
    }
}
