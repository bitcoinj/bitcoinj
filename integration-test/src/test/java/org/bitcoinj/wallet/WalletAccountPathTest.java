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
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.HDPath;
import org.bitcoinj.script.Script;
import org.bitcoinj.utils.Network;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.stream.Stream;

import static org.bitcoinj.script.Script.ScriptType.P2PKH;
import static org.bitcoinj.script.Script.ScriptType.P2TR;
import static org.bitcoinj.script.Script.ScriptType.P2WPKH;
import static org.bitcoinj.utils.Network.MAIN;
import static org.bitcoinj.utils.Network.TEST;
import static org.bitcoinj.wallet.KeyChainGroupStructure.BIP43;
import static org.bitcoinj.wallet.KeyChainGroupStructure.BIP32;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Create new Wallets in a temp directory and make sure their account paths are correct.
 */
public class WalletAccountPathTest {
    private static final String testWalletMnemonic = "panda diary marriage suffer basic glare surge auto scissors describe sell unique";

    @TempDir File tempDir;
    File walletFile;

    @BeforeEach
    void setupTest() {
        walletFile = new File(tempDir, "test.wallet");
    }

    @MethodSource("walletStructureParams")
    @ParameterizedTest(name = "path {1} generated for {2}, {3}")
    void walletStructurePathTest2(KeyChainGroupStructure structure, HDPath expectedPath, Script.ScriptType scriptType,
                                  Network network) throws IOException, UnreadableWalletException {
        // When we create a wallet with parameterized structure, network, and scriptType
        Wallet wallet = createWallet(walletFile, network.networkParameters(), structure, scriptType);

        // Then the account path is as expected
        assertEquals(expectedPath, wallet.getActiveKeyChain().getAccountPath());
    }

    private static Stream<Arguments> walletStructureParams() {
        return Stream.of(
            // Note: For BIP32 wallets the Network does not affect the path
            Arguments.of(BIP32, "M/0H", P2PKH,  MAIN),
            Arguments.of(BIP32, "M/0H", P2PKH,  TEST),
            Arguments.of(BIP32, "M/1H", P2WPKH, MAIN),
            Arguments.of(BIP32, "M/1H", P2WPKH, TEST),
            Arguments.of(BIP43, "M/44H/0H/0H", P2PKH, MAIN),
            Arguments.of(BIP43, "M/44H/1H/0H", P2PKH, TEST),
            Arguments.of(BIP43, "M/84H/0H/0H", P2WPKH, MAIN),
            Arguments.of(BIP43, "M/84H/1H/0H", P2WPKH, TEST),
            Arguments.of(BIP43, "M/86H/0H/0H", P2TR, MAIN),
            Arguments.of(BIP43, "M/86H/1H/0H", P2TR, TEST)
        );
    }

    // Create a wallet, save it to a file, then reload from a file
    private static Wallet createWallet(File walletFile, NetworkParameters params, KeyChainGroupStructure structure, Script.ScriptType outputScriptType) throws IOException, UnreadableWalletException {
        Context.propagate(new Context(params));
        DeterministicSeed seed = new DeterministicSeed(testWalletMnemonic, null, "", Instant.now().getEpochSecond());
        Wallet wallet = Wallet.fromSeed(params, seed, outputScriptType, structure);
        wallet.saveToFile(walletFile);
        return Wallet.loadFromFile(walletFile);
    }
}
