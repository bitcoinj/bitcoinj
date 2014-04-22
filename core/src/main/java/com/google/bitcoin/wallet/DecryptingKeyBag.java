/**
 * Copyright 2014 The bitcoinj authors.
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

package com.google.bitcoin.wallet;

import com.google.bitcoin.core.ECKey;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A DecryptingKeyBag filters a pre-existing key bag, decrypting keys as they are requested using the provided
 * AES key.
 */
public class DecryptingKeyBag implements KeyBag {
    protected final KeyBag target;
    protected final KeyParameter aesKey;

    public DecryptingKeyBag(KeyBag target, KeyParameter aesKey) {
        this.target = checkNotNull(target);
        this.aesKey = checkNotNull(aesKey);
    }

    @Nullable
    private ECKey maybeDecrypt(ECKey key) {
        return key == null ? null : key.decrypt(aesKey);
    }

    @Nullable
    @Override
    public ECKey findKeyFromPubHash(byte[] pubkeyHash) {
        return maybeDecrypt(target.findKeyFromPubHash(pubkeyHash));
    }

    @Nullable
    @Override
    public ECKey findKeyFromPubKey(byte[] pubkey) {
        return maybeDecrypt(target.findKeyFromPubKey(pubkey));
    }
}
