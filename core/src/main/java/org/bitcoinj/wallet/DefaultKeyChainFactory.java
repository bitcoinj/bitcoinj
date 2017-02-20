/*
 * Copyright 2014 devrandom
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

import org.bitcoinj.crypto.*;

import com.google.common.collect.ImmutableList;

/**
 * Default factory for creating keychains while de-serializing.
 */
public class DefaultKeyChainFactory implements KeyChainFactory {
    @Override
    public DeterministicKeyChain makeKeyChain(Protos.Key key, Protos.Key firstSubKey, DeterministicSeed seed, KeyCrypter crypter, boolean isMarried) {
        DeterministicKeyChain chain;
        if (isMarried)
            chain = new MarriedKeyChain(seed, crypter);
        else
            chain = new DeterministicKeyChain(seed, crypter);
        return chain;
    }

    @Override
    public DeterministicKeyChain makeKeyChain(Protos.Key key, Protos.Key firstSubKey, DeterministicSeed seed,
                                              KeyCrypter crypter, boolean isMarried, ImmutableList<ChildNumber> accountPath) {
        DeterministicKeyChain chain;
        if (isMarried)
            chain = new MarriedKeyChain(seed, crypter);
        else
            chain = new DeterministicKeyChain(seed, crypter, accountPath);
        return chain;
    }

    @Override
    public DeterministicKeyChain makeWatchingKeyChain(Protos.Key key, Protos.Key firstSubKey, DeterministicKey accountKey,
                                                      boolean isFollowingKey, boolean isMarried) throws UnreadableWalletException {
        DeterministicKeyChain chain;
        if (isMarried)
            chain = new MarriedKeyChain(accountKey);
        else
            chain = new DeterministicKeyChain(accountKey, isFollowingKey, accountKey.getPath());
        return chain;
    }
}
