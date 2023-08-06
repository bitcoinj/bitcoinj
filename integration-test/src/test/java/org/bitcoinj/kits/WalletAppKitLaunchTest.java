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

package org.bitcoinj.kits;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.core.listeners.DownloadProgressTracker;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code WalletAppKit.launch()} functional/integration test. Uses {@link BitcoinNetwork#TESTNET} so is {@link org.junit.jupiter.api.Disabled}.
 * To run this test comment-out the {@code @Disabled} annotation.
 */
@Disabled
public class WalletAppKitLaunchTest {
    static final BitcoinNetwork network = BitcoinNetwork.TESTNET;
    static final String prefix = "prefix";
    static final int MAX_CONNECTIONS = 3;

    // Launch the kit and immediately stop it
    @Test
    public void launchAndStop(@TempDir File tempDir) {
        try (WalletAppKit kit = WalletAppKit.launch(BitcoinNetwork.TESTNET, tempDir, prefix)) {
            assertTrue(kit.isRunning());
        }
    }

    // Launch the kit setting max connections and then stop it
    @Test
    public void launchSetMaxConnAndStop(@TempDir File tempDir) {
        try (WalletAppKit kit = WalletAppKit.launch(BitcoinNetwork.TESTNET, tempDir, prefix, MAX_CONNECTIONS)) {
            assertTrue(kit.isRunning());
        }
    }

    // Launch the kit, disable bloom filters and then stop it
    @Test
    public void launchNoBloomAndStop(@TempDir File tempDir) {
        try (WalletAppKit kit = WalletAppKit.launch(BitcoinNetwork.TESTNET, tempDir, prefix)) {
            assertTrue(kit.isRunning());
            kit.peerGroup().setBloomFilteringEnabled(false);
        }
    }

    // Launch the kit using a configurer to set a download listener, wait for synchronization and then stop
    @Test
    public void launchSetListenerSyncAndStop(@TempDir File tempDir) {
        DownloadProgressTracker downloadListener = new DownloadProgressTracker();
        try (WalletAppKit kit = WalletAppKit.launch(BitcoinNetwork.TESTNET, tempDir, prefix, k -> k.setDownloadListener(downloadListener))) {
            assertTrue(kit.isRunning());
            long height = downloadListener.getFuture().join();
            assertTrue(height > 0);
            System.out.println("Chain download completed with blockheight = " + height);
        }
    }
}
