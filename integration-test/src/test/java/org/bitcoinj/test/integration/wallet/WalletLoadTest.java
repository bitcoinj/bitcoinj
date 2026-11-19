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

package org.bitcoinj.test.integration.wallet;

import org.bitcoinj.core.Context;
import org.bitcoinj.crypto.HDPath;
import org.bitcoinj.wallet.UnreadableWalletException;
import org.bitcoinj.wallet.Wallet;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.bitcoinj.test.integration.wallet.WalletTestParams.WALLET_BIRTHDAY;
import static org.bitcoinj.test.integration.wallet.WalletTestParams.WALLET_FILE;
import static org.bitcoinj.test.integration.wallet.WalletTestParams.WALLET_MNEMONIC;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Basic test of loading a wallet from a known test file
 */
public class WalletLoadTest {
    @Test
    void basicWalletLoadTest() throws UnreadableWalletException {
        Context.propagate(new Context());
        Wallet wallet = Wallet.loadFromFile(WALLET_FILE);

        Instant creation = wallet.getKeyChainSeed().getCreationTime().get();
        assertEquals(WALLET_BIRTHDAY, creation, "unexpected creation timestamp");

        String mnemonic = wallet.getKeyChainSeed().getMnemonicString();
        assertEquals(WALLET_MNEMONIC, mnemonic, "unexpected mnemonic");

        HDPath accountPath = wallet.getActiveKeyChain().accountFullPath();
        assertEquals(HDPath.parsePath("m/0H"), accountPath);
    }
}
