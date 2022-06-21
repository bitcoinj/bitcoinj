/*
 * Copyright 2014 devrandom
 * Copyright 2019 Andreas Schildbach
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

import org.bitcoinj.base.ScriptType;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.KeyCrypter;

import java.util.List;

/**
 * Default factory for creating keychains while de-serializing.
 */
public class DefaultKeyChainFactory implements KeyChainFactory {
    @Override
    public DeterministicKeyChain makeKeyChain(DeterministicSeed seed, KeyCrypter crypter, boolean isMarried,
                                              ScriptType outputScriptType, List<ChildNumber> accountPath) {
        DeterministicKeyChain chain;
        if (isMarried)
            chain = new MarriedKeyChain(seed, crypter, outputScriptType, accountPath);
        else
            chain = new DeterministicKeyChain(seed, crypter, outputScriptType, accountPath);
        return chain;
    }

    @Override
    public DeterministicKeyChain makeWatchingKeyChain(DeterministicKey accountKey, boolean isFollowingKey,
            boolean isMarried, ScriptType outputScriptType) throws UnreadableWalletException {
        DeterministicKeyChain chain;
        if (isMarried)
            chain = new MarriedKeyChain(accountKey, outputScriptType);
        else if (isFollowingKey)
            chain = DeterministicKeyChain.builder().watchAndFollow(accountKey).outputScriptType(outputScriptType).build();
        else
            chain = DeterministicKeyChain.builder().watch(accountKey).outputScriptType(outputScriptType).build();
        return chain;
    }

    @Override
    public DeterministicKeyChain makeSpendingKeyChain(DeterministicKey accountKey, boolean isMarried,
            ScriptType outputScriptType) throws UnreadableWalletException {
        DeterministicKeyChain chain;
        if (isMarried)
            chain = new MarriedKeyChain(accountKey, outputScriptType);
        else
            chain = DeterministicKeyChain.builder().spend(accountKey).outputScriptType(outputScriptType).build();
        return chain;
    }
}
