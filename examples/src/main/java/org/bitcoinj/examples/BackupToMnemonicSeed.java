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

package org.bitcoinj.examples;

import org.bitcoinj.base.ScriptType;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.internal.InternalUtils;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.Wallet;

/**
 * The following example shows you how to create a deterministic seed from a hierarchical deterministic wallet represented as a mnemonic code.
 * This seed can be used to fully restore your wallet. The RestoreFromSeed.java example shows how to load the wallet from this seed.
 * 
 * In Bitcoin Improvement Proposal (BIP) 39 and BIP 32 describe the details about hierarchical deterministic wallets and mnemonic sentences
 * https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */
public class BackupToMnemonicSeed {

    public static void main(String[] args) {

        NetworkParameters params = TestNet3Params.get();
        Wallet wallet = Wallet.createDeterministic(params, ScriptType.P2PKH);

        DeterministicSeed seed = wallet.getKeyChainSeed();
        System.out.println("seed: " + seed.toString());

        System.out.println("creation time: " + seed.getCreationTimeSeconds());
        System.out.println("mnemonicCode: " + InternalUtils.SPACE_JOINER.join(seed.getMnemonicCode()));
    }
}
