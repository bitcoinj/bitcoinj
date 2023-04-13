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

import org.bitcoinj.base.ScriptType;
import org.bitcoinj.wallet.KeyChainGroupStructure;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;

import static org.bitcoinj.base.BitcoinNetwork.REGTEST;
import static org.bitcoinj.base.ScriptType.P2WPKH;
import static org.bitcoinj.wallet.KeyChainGroupStructure.BIP43;

/**
 * Test WalletAppKit
 */
public class WalletAppKitTest {
    @Rule
    public TemporaryFolder tmpFolder = new TemporaryFolder();
    static final String filePrefix = "UnitTestWalletAppKit";

    @Test
    public void constructAndClose() throws IOException {
        WalletAppKit kit = new WalletAppKit(REGTEST, P2WPKH, BIP43, tmpFolder.newFolder(), filePrefix);
        kit.close();
    }

    @Test
    public void constructAndCloseTwice() throws IOException {
        WalletAppKit kit = new WalletAppKit(REGTEST, P2WPKH, BIP43, tmpFolder.newFolder(), filePrefix);
        kit.close();
        kit.close();
    }

    @Test
    public void launchAndClose() throws IOException {
        WalletAppKit kit = WalletAppKit.launch(REGTEST, tmpFolder.newFolder(), filePrefix);
        kit.close();
    }

    @Test
    public void launchAndCloseTwice() throws IOException {
        WalletAppKit kit = WalletAppKit.launch(REGTEST, tmpFolder.newFolder(), filePrefix);
        kit.close();
        kit.close();
    }
}
