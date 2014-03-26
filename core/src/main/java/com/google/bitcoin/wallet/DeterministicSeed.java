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

import com.google.bitcoin.crypto.*;
import org.bitcoinj.wallet.Protos;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.util.encoders.Hex;

import javax.annotation.Nullable;
import java.io.IOException;
import java.util.List;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * Holds the seed bytes for the BIP32 deterministic wallet algorithm, inside a
 * {@link com.google.bitcoin.wallet.DeterministicKeyChain}. The purpose of this wrapper is to simplify the encryption
 * code.
 */
public class DeterministicSeed implements EncryptableItem {
    @Nullable private final byte[] unencryptedSeed;
    @Nullable private final EncryptedData encryptedSeed;
    private final long creationTimeSeconds;

    private static MnemonicCode MNEMONIC_CODE;
    private static synchronized MnemonicCode getCachedMnemonicCode() {
        try {
            // This object can be large and has to load the word list from disk, so we lazy cache it.
            if (MNEMONIC_CODE == null) {
                MNEMONIC_CODE = new MnemonicCode();
            }
            return MNEMONIC_CODE;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

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

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link com.google.bitcoin.crypto.MnemonicCode} for more
     * details on this scheme.
     * @param words A list of 12 words.
     * @param creationTimeSeconds When the seed was originally created, UNIX time.
     * @throws MnemonicException if there is a problem decoding the words.
     */
    public DeterministicSeed(List<String> words, long creationTimeSeconds) throws MnemonicException.MnemonicChecksumException, MnemonicException.MnemonicLengthException, MnemonicException.MnemonicWordException {
        this(getCachedMnemonicCode().toEntropy(words), creationTimeSeconds);
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
            return "DeterministicSeed " + toHexString();
    }

    /** Returns the seed as hex or null if encrypted. */
    @Nullable
    public String toHexString() {
        if (unencryptedSeed != null)
            return new String(Hex.encode(unencryptedSeed));
        else
            return null;
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

    public DeterministicSeed encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) {
        checkState(encryptedSeed == null, "Trying to encrypt seed twice");
        checkState(unencryptedSeed != null, "Seed bytes missing so cannot encrypt");
        EncryptedData data = keyCrypter.encrypt(unencryptedSeed, aesKey);
        return new DeterministicSeed(data, creationTimeSeconds);
    }

    public DeterministicSeed decrypt(KeyCrypter crypter, KeyParameter aesKey) {
        checkState(isEncrypted());
        checkNotNull(encryptedSeed);
        return new DeterministicSeed(crypter.decrypt(encryptedSeed, aesKey), creationTimeSeconds);
    }

    /** Returns a list of words that represent the seed, or IllegalStateException if the seed is encrypted or missing. */
    public List<String> toMnemonicCode(MnemonicCode code) {
        try {
            if (isEncrypted())
                throw new IllegalStateException("The seed is encrypted");
            final byte[] seed = checkNotNull(getSecretBytes());
            return code.toMnemonic(seed);
        } catch (MnemonicException.MnemonicLengthException e) {
            throw new RuntimeException(e);  // Cannot happen.
        }
    }

    /** Returns a list of words that represent the seed, or IllegalStateException if the seed is encrypted or missing. */
    public List<String> toMnemonicCode() {
        return toMnemonicCode(getCachedMnemonicCode());
    }
}
