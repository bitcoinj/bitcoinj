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

package org.bitcoincashj.wallet;

import org.bitcoincashj.crypto.DeterministicKey;
import org.bitcoincashj.crypto.KeyCrypter;

/**
 * Factory interface for creation keychains while de-serializing a wallet.
 */
public interface KeyChainFactory {
    /**
     * Make a keychain (but not a watching one).
     *
     * @param key the protobuf for the root key
     * @param firstSubKey the protobuf for the first child key (normally the parent of the external subchain)
     * @param seed the seed
     * @param crypter the encrypted/decrypter
     * @param isMarried whether the keychain is leading in a marriage
     */
    DeterministicKeyChain makeKeyChain(Protos.Key key, Protos.Key firstSubKey, DeterministicSeed seed, KeyCrypter crypter, boolean isMarried);

    /**
     * Make a watching keychain.
     *
     * <p>isMarried and isFollowingKey must not be true at the same time.
     *
     * @param key the protobuf for the account key
     * @param firstSubKey the protobuf for the first child key (normally the parent of the external subchain)
     * @param accountKey the account extended public key
     * @param isFollowingKey whether the keychain is following in a marriage
     * @param isMarried whether the keychain is leading in a marriage
     */
    DeterministicKeyChain makeWatchingKeyChain(Protos.Key key, Protos.Key firstSubKey, DeterministicKey accountKey, boolean isFollowingKey, boolean isMarried) throws UnreadableWalletException;
}
