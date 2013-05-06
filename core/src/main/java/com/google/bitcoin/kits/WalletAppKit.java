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

package com.google.bitcoin.kits;

import com.google.bitcoin.core.*;
import com.google.bitcoin.discovery.DnsDiscovery;
import com.google.bitcoin.store.BlockStoreException;
import com.google.bitcoin.store.SPVBlockStore;
import com.google.bitcoin.store.WalletProtobufSerializer;
import com.google.common.util.concurrent.AbstractIdleService;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.util.concurrent.TimeUnit;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * Utility class that wraps the boilerplate needed to set up a new SPV bitcoinj app. Instantiate it with a directory
 * and file prefix, optionally configure a few things, then use start or startAndWait. The object will construct and
 * configure a {@link BlockChain}, {@link SPVBlockStore}, {@link Wallet} and {@link PeerGroup}. Startup will be
 * considered complete once the block chain has fully synchronized, so it can take a while. Once complete, you can
 * go ahead and add the listeners you need to the underlying objects.
 */
public class WalletAppKit extends AbstractIdleService {
    protected final String filePrefix;
    protected final NetworkParameters params;
    protected volatile BlockChain vChain;
    protected volatile SPVBlockStore vStore;
    protected volatile Wallet vWallet;
    protected volatile PeerGroup vPeerGroup;
    protected volatile boolean vUseAutoSave = true;

    protected final File directory;
    protected volatile File vChainFile, vWalletFile;

    protected volatile InetAddress[] vPeerAddresses;

    public WalletAppKit(NetworkParameters params, File directory, String filePrefix) {
        this.params = checkNotNull(params);
        this.directory = checkNotNull(directory);
        this.filePrefix = checkNotNull(filePrefix);
    }

    public WalletAppKit setPeerNodes(InetAddress... addresses) {
        checkState(state() == State.NEW, "Cannot call after startup");
        this.vPeerAddresses = addresses;
        return this;
    }

    public WalletAppKit setAutoSave(boolean value) {
        checkState(state() == State.NEW, "Cannot call after startup");
        vUseAutoSave = value;
        return this;
    }

    @Override
    protected void startUp() throws Exception {
        if (!directory.exists()) {
            if (!directory.mkdir()) {
                throw new IOException("Could not create named directory.");
            }
        }
        FileInputStream walletStream = null;
        try {
            vChainFile = new File(directory, filePrefix + ".spvchain");
            vWalletFile = new File(directory, filePrefix + ".wallet");
            boolean shouldReplayWallet = vWalletFile.exists() && !vChainFile.exists();
            if (vWalletFile.exists()) {
                walletStream = new FileInputStream(vWalletFile);
                vWallet = new WalletProtobufSerializer().readWallet(walletStream);
                if (shouldReplayWallet)
                    vWallet.clearTransactions(0);
            } else {
                vWallet = new Wallet(params);
            }
            if (vUseAutoSave) vWallet.autosaveToFile(vWalletFile, 1, TimeUnit.SECONDS, null);
            vStore = new SPVBlockStore(params, vChainFile);
            vChain = new BlockChain(params, vWallet, vStore);
            vPeerGroup = new PeerGroup(params, vChain);
            vPeerGroup.addWallet(vWallet);
            if (vPeerAddresses != null) {
                for (InetAddress addr : vPeerAddresses) vPeerGroup.addAddress(addr);
                vPeerAddresses = null;
            } else {
                vPeerGroup.addPeerDiscovery(new DnsDiscovery(params));
            }
            vPeerGroup.startAndWait();
            vPeerGroup.downloadBlockChain();
            // Make sure we shut down cleanly.
            Runtime.getRuntime().addShutdownHook(new Thread() {
                @Override public void run() {
                    try {
                        WalletAppKit.this.stopAndWait();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            });
        } catch (BlockStoreException e) {
            throw new IOException(e);
        } finally {
            if (walletStream != null) walletStream.close();
        }
    }

    @Override
    protected void shutDown() throws Exception {
        // Runs in a separate thread.
        try {
            vPeerGroup.stopAndWait();
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

    public NetworkParameters params() {
        return params;
    }

    public BlockChain chain() {
        checkState(state() == State.RUNNING, "Cannot call until startup is complete");
        return vChain;
    }

    public SPVBlockStore store() {
        checkState(state() == State.RUNNING, "Cannot call until startup is complete");
        return vStore;
    }

    public Wallet wallet() {
        checkState(state() == State.RUNNING, "Cannot call until startup is complete");
        return vWallet;
    }

    public PeerGroup peerGroup() {
        checkState(state() == State.RUNNING, "Cannot call until startup is complete");
        return vPeerGroup;
    }

    public File directory() {
        return directory;
    }
}
