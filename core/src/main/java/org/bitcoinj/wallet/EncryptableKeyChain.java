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

import org.bitcoinj.crypto.KeyCrypter;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;

/**
 * An encryptable key chain is a key-chain that can be encrypted with a user-provided password or AES key.
 */
public interface EncryptableKeyChain extends KeyChain {
    /**
     * Takes the given password, which should be strong, derives a key from it and then invokes
     * {@link #toEncrypted(KeyCrypter, KeyParameter)} with
     * {@link KeyCrypterScrypt} as the crypter.
     *
     * @return The derived key, in case you wish to cache it for future use.
     */
    EncryptableKeyChain toEncrypted(CharSequence password);

    /**
     * Returns a new keychain holding identical/cloned keys to this chain, but encrypted under the given key.
     * Old keys and keychains remain valid and so you should ensure you don't accidentally hold references to them.
     */
    EncryptableKeyChain toEncrypted(KeyCrypter keyCrypter, KeyParameter aesKey);

    /**
     * Decrypts the key chain with the given password. See {@link #toDecrypted(KeyParameter)}
     * for details.
     */
    EncryptableKeyChain toDecrypted(CharSequence password);

    /**
     * Decrypt the key chain with the given AES key and whatever {@link KeyCrypter} is already set. Note that if you
     * just want to spend money from an encrypted wallet, don't decrypt the whole thing first. Instead, set the
     * {@link SendRequest#aesKey} field before asking the wallet to build the send.
     *
     * @param aesKey AES key to use (normally created using KeyCrypter#deriveKey and cached as it is time consuming to
     *               create from a password)
     * @throws KeyCrypterException Thrown if the wallet decryption fails. If so, the wallet state is unchanged.
     */
    EncryptableKeyChain toDecrypted(KeyParameter aesKey);

    boolean checkPassword(CharSequence password);
    boolean checkAESKey(KeyParameter aesKey);

    /** Returns the key crypter used by this key chain, or null if it's not encrypted. */
    @Nullable
    KeyCrypter getKeyCrypter();
}
