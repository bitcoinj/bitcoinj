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

package org.bitcoinj.crypto;

import org.bitcoinj.wallet.Protos;

import javax.annotation.Nullable;

/**
 * Provides a uniform way to access something that can be optionally encrypted with a
 * {@link org.bitcoinj.crypto.KeyCrypter}, yielding an {@link org.bitcoinj.crypto.EncryptedData}, and
 * which can have a creation time associated with it.
 */
public interface EncryptableItem {
    /** Returns whether the item is encrypted or not. If it is, then {@link #getSecretBytes()} will return null. */
    boolean isEncrypted();

    /** Returns the raw bytes of the item, if not encrypted, or null if encrypted or the secret is missing. */
    @Nullable
    byte[] getSecretBytes();

    /** Returns the initialization vector and encrypted secret bytes, or null if not encrypted. */
    @Nullable
    EncryptedData getEncryptedData();

    /** Returns an enum constant describing what algorithm was used to encrypt the key or UNENCRYPTED. */
    Protos.Wallet.EncryptionType getEncryptionType();

    /** Returns the time in seconds since the UNIX epoch at which this encryptable item was first created/derived. */
    long getCreationTimeSeconds();
}
