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

package org.bitcoinj.wallet;

import org.bitcoinj.core.Context;
import org.bitcoinj.crypto.HDPath;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Basic test of loading a wallet from a known test file
 */
public class WalletLoadTest {
    private static final File walletFile = new File("src/test/resources/org/bitcoinj/wallet/panda-test-wallet.wallet");
    private static final String testWalletMnemonic = "panda diary marriage suffer basic glare surge auto scissors describe sell unique";
    private static final long testWalletCreation = 1554102000;

    @Test
    void basicWalletLoadTest() throws UnreadableWalletException {
        Context.propagate(new Context());
        Wallet wallet = Wallet.loadFromFile(walletFile);

        long creation = wallet.getKeyChainSeed().getCreationTimeSeconds();
        assertEquals(testWalletCreation, creation, "unexpected creation timestamp");

        String mnemonic = wallet.getKeyChainSeed().getMnemonicString();
        assertEquals(testWalletMnemonic, mnemonic, "unexpected mnemonic");

        HDPath accountPath = wallet.getActiveKeyChain().getAccountPath();
        assertEquals(HDPath.parsePath("M/0H"), accountPath);
    }
}
