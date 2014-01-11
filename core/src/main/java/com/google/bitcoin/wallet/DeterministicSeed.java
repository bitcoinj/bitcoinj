/**
 * Copyright 2014 Google Inc.
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

import com.google.bitcoin.crypto.EncryptableItem;
import com.google.bitcoin.crypto.EncryptedData;
import org.bitcoinj.wallet.Protos;
import org.spongycastle.util.encoders.Hex;

import javax.annotation.Nullable;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * Holds the seed bytes for the BIP32 deterministic wallet algorithm, inside a
 * {@link com.google.bitcoin.wallet.DeterministicKeyChain}. The purpose of this wrapper is to simplify the encryption
 * code.
 */
class DeterministicSeed implements EncryptableItem {
    @Nullable private final byte[] unencryptedSeed;
    @Nullable private final EncryptedData encryptedSeed;
    private final long creationTimeSeconds;

    public DeterministicSeed(byte[] unencryptedSeed, long creationTimeSeconds) {
        this.unencryptedSeed = checkNotNull(unencryptedSeed);
        this.encryptedSeed = null;
        this.creationTimeSeconds = creationTimeSeconds;
    }

    public DeterministicSeed(EncryptedData encryptedSeed, long creationTimeSeconds) {
        this.unencryptedSeed = null;
        this.encryptedSeed = checkNotNull(encryptedSeed);
        this.creationTimeSeconds = creationTimeSeconds;
    }

    @Override
    public boolean isEncrypted() {
        checkState(unencryptedSeed != null || encryptedSeed != null);
        return encryptedSeed != null;
    }

    @Override
    public String toString() {
        if (isEncrypted())
            return "DeterministicSeed [encrypted]";
        else
            return "DeterministicSeed " + new String(Hex.encode(unencryptedSeed));
    }

    @Nullable
    @Override
    public byte[] getSecretBytes() {
        return unencryptedSeed;
    }

    @Nullable
    @Override
    public EncryptedData getEncryptedData() {
        return encryptedSeed;
    }

    @Override
    public Protos.Wallet.EncryptionType getEncryptionType() {
        return Protos.Wallet.EncryptionType.ENCRYPTED_SCRYPT_AES;
    }

    @Override
    public long getCreationTimeSeconds() {
        return creationTimeSeconds;
    }
}
