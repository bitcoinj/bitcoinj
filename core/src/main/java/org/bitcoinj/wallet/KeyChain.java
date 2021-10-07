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

package org.bitcoinj.wallet;

import org.bitcoinj.core.ECKey;

import java.util.List;

/**
 * <p>A KeyChain is a class that stores a collection of keys for a {@link Wallet}. Key chains
 * are expected to be able to look up keys given a hash (i.e. address) or pubkey bytes, and provide keys on request
 * for a given purpose. They can inform event listeners about new keys being added.</p>
 *
 * <p>However it is important to understand what this interface does <i>not</i> provide. It cannot encrypt or decrypt
 * keys, for instance you need an implementor of {@link EncryptableKeyChain}. It cannot have keys imported into it,
 * that you to use a method of a specific key chain instance, such as {@link BasicKeyChain}. The reason for these
 * restrictions is to support key chains that may be handled by external hardware or software, or which are derived
 * deterministically from a seed (and thus the notion of importing a key is meaningless).</p>
 */
public interface KeyChain {
    /** Returns true if the given key is in the chain. */
    boolean hasKey(ECKey key);

    enum KeyPurpose {
        RECEIVE_FUNDS,
        CHANGE,
        REFUND,
        AUTHENTICATION
    }

    /** Obtains a number of key/s intended for the given purpose. The chain may create new key/s, derive, or re-use an old one. */
    List<? extends ECKey> getKeys(KeyPurpose purpose, int numberOfKeys);

    /** Obtains a key intended for the given purpose. The chain may create a new key, derive one, or re-use an old one. */
    ECKey getKey(KeyPurpose purpose);
}
