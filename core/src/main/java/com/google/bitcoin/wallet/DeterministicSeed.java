/**
 * Copyright 2014 Google Inc.
 * Copyright 2014 Andreas Schildbach
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
import com.google.bitcoin.store.UnreadableWalletException;
import com.google.common.base.Joiner;
import com.google.common.base.Preconditions;
import com.google.common.base.Splitter;

import org.bitcoinj.wallet.Protos;
import org.spongycastle.crypto.params.KeyParameter;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;

import static com.google.bitcoin.core.Utils.HEX;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * Holds the seed bytes for the BIP32 deterministic wallet algorithm, inside a
 * {@link com.google.bitcoin.wallet.DeterministicKeyChain}. The purpose of this wrapper is to simplify the encryption
 * code.
 */
public class DeterministicSeed implements EncryptableItem {
    // It would take more than 10^12 years to brute-force a 128 bit seed using $1B worth
    // of computing equipment.
    public static final int DEFAULT_SEED_ENTROPY_BITS = 128;
    public static final int MAX_SEED_ENTROPY_BITS = 512;
    public static final String UTF_8 = "UTF-8";

    @Nullable private final byte[] unencryptedSeed;
    @Nullable private final EncryptedData encryptedSeed;
    @Nullable private List<String> mnemonicCode;
    @Nullable private EncryptedData encryptedMnemonicCode;
    private final long creationTimeSeconds;

    private static MnemonicCode MNEMONIC_CODEC;

    private static synchronized MnemonicCode getCachedMnemonicCodec() {
        try {
            // This object can be large and has to load the word list from disk, so we lazy cache it.
            if (MNEMONIC_CODEC == null) {
                MNEMONIC_CODEC = new MnemonicCode();
            }
            return MNEMONIC_CODEC;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    DeterministicSeed(byte[] unencryptedSeed, List<String> mnemonic, long creationTimeSeconds) {
        this.unencryptedSeed = checkNotNull(unencryptedSeed);
        this.encryptedSeed = null;
        this.mnemonicCode = mnemonic;
        this.encryptedMnemonicCode = null;
        this.creationTimeSeconds = creationTimeSeconds;
    }

    /**
     * Constructs a seed from bytes.  The mnemonic phrase is unknown.
     */
    public DeterministicSeed(byte[] unencryptedSeed, long creationTimeSeconds) {
        this(unencryptedSeed, null, creationTimeSeconds);
    }

    DeterministicSeed(EncryptedData encryptedSeed, EncryptedData encryptedMnemonic, long creationTimeSeconds) {
        this.unencryptedSeed = null;
        this.mnemonicCode = null;
        this.encryptedSeed = checkNotNull(encryptedSeed);
        this.encryptedMnemonicCode = encryptedMnemonic;
        this.creationTimeSeconds = creationTimeSeconds;
    }

    DeterministicSeed(EncryptedData encryptedSeed, long creationTimeSeconds) {
        this(encryptedSeed, null, creationTimeSeconds);
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link com.google.bitcoin.crypto.MnemonicCode} for more
     * details on this scheme.
     * @param mnemonicCode A list of words.
     * @param passphrase A user supplied passphrase, or an empty string if there is no passphrase
     * @param creationTimeSeconds When the seed was originally created, UNIX time.
     */
    public DeterministicSeed(List<String> mnemonicCode, String passphrase, long creationTimeSeconds) {
        this(getCachedMnemonicCodec().toSeed(mnemonicCode, passphrase), mnemonicCode, creationTimeSeconds);
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link com.google.bitcoin.crypto.MnemonicCode} for more
     * details on this scheme.
     * @param random Entropy source
     * @param bits number of bits, must be divisible by 32
     * @param passphrase A user supplied passphrase, or an empty string if there is no passphrase
     * @param creationTimeSeconds When the seed was originally created, UNIX time.
     */
    public DeterministicSeed(SecureRandom random, int bits, String passphrase, long creationTimeSeconds) {
        byte[] entropy = getEntropy(random, bits);
        try {
            this.mnemonicCode = getCachedMnemonicCodec().toMnemonic(entropy);
        } catch (MnemonicException.MnemonicLengthException e) {
            // cannot happen
            throw new RuntimeException(e);
        }
        this.unencryptedSeed = getCachedMnemonicCodec().toSeed(mnemonicCode, passphrase);
        this.encryptedSeed = null;
        this.creationTimeSeconds = creationTimeSeconds;
    }

    private static byte[] getEntropy(SecureRandom random, int bits) {
        Preconditions.checkArgument(bits >= DEFAULT_SEED_ENTROPY_BITS, "requested entropy size too small");
        Preconditions.checkArgument(bits <= MAX_SEED_ENTROPY_BITS, "requested entropy size too large");
        Preconditions.checkArgument(bits % 32 == 0, "requested entropy size not divisible by 32");

        byte[] seed = new byte[bits / 8];
        random.nextBytes(seed);
        return seed;
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
            return "DeterministicSeed " + toHexString() +
                    ((mnemonicCode != null) ? " " + Joiner.on(" ").join(mnemonicCode) : "");
    }

    /** Returns the seed as hex or null if encrypted. */
    @Nullable
    public String toHexString() {
        if (unencryptedSeed != null)
            return HEX.encode(unencryptedSeed);
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

    public EncryptableItem getMnemonicEncryptableItem() {
        return new EncryptableItem() {
            @Override
            public boolean isEncrypted() {
                return DeterministicSeed.this.isEncrypted();
            }

            @Nullable
            @Override
            public byte[] getSecretBytes() {
                return getMnemonicAsBytes();
            }

            @Nullable
            @Override
            public EncryptedData getEncryptedData() {
                return encryptedMnemonicCode;
            }

            @Override
            public Protos.Wallet.EncryptionType getEncryptionType() {
                return Protos.Wallet.EncryptionType.ENCRYPTED_SCRYPT_AES;
            }

            @Override
            public long getCreationTimeSeconds() {
                return creationTimeSeconds;
            }
        };
    }

    public DeterministicSeed encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) {
        checkState(encryptedSeed == null, "Trying to encrypt seed twice");
        checkState(unencryptedSeed != null, "Seed bytes missing so cannot encrypt");
        EncryptedData seed = keyCrypter.encrypt(unencryptedSeed, aesKey);
        EncryptedData mnemonic = (mnemonicCode != null) ? keyCrypter.encrypt(getMnemonicAsBytes(), aesKey) : null;
        return new DeterministicSeed(seed, mnemonic, creationTimeSeconds);
    }

    private byte[] getMnemonicAsBytes() {
        try {
            return Joiner.on(" ").join(mnemonicCode).getBytes(UTF_8);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public DeterministicSeed decrypt(KeyCrypter crypter, KeyParameter aesKey) {
        checkState(isEncrypted());
        checkNotNull(encryptedSeed);
        byte[] seed = crypter.decrypt(encryptedSeed, aesKey);
        List<String> mnemonic = null;
        try {
            if (encryptedMnemonicCode != null)
                mnemonic = decodeMnemonicCode(crypter.decrypt(encryptedMnemonicCode, aesKey));
        } catch (UnreadableWalletException e) {
            // TODO what is the best way to handle this exception?
            throw new RuntimeException(e);
        }
        return new DeterministicSeed(seed, mnemonic, creationTimeSeconds);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        DeterministicSeed seed = (DeterministicSeed) o;

        if (creationTimeSeconds != seed.creationTimeSeconds) return false;
        if (encryptedSeed != null) {
            if (seed.encryptedSeed == null) return false;
            if (!encryptedSeed.equals(seed.encryptedSeed)) return false;
        } else {
            if (!Arrays.equals(unencryptedSeed, seed.unencryptedSeed)) return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int result = encryptedSeed != null ? encryptedSeed.hashCode() : Arrays.hashCode(unencryptedSeed);
        result = 31 * result + (int) (creationTimeSeconds ^ (creationTimeSeconds >>> 32));
        return result;
    }

    /**
     * Check if our mnemonic is a valid mnemonic phrase for our word list.
     * Does nothing if we are encrypted.
     *
     * @throws com.google.bitcoin.crypto.MnemonicException if check fails
     */
    public void check() throws MnemonicException {
        if (mnemonicCode != null)
            getCachedMnemonicCodec().check(mnemonicCode);
    }

    /** Get the mnemonic code, or null if unknown. */
    @Nullable
    public List<String> getMnemonicCode() {
        return mnemonicCode;
    }

    /** Set encrypted mnemonic code.  Used by protobuf deserializer. */
    public void setEncryptedMnemonicCode(EncryptedData encryptedMnemonicCode) {
        this.encryptedMnemonicCode = encryptedMnemonicCode;
    }

    /** Set mnemonic code from UTF-8 encoded bytes. */
    public void setMnemonicCode(@Nullable byte[] mnemonicCode) throws UnreadableWalletException {
        this.mnemonicCode = decodeMnemonicCode(mnemonicCode);
    }

    /** Whether the mnemonic code is known for this seed. */
    public boolean hasMnemonicCode() {
        return mnemonicCode != null || encryptedMnemonicCode != null;
    }

    private List<String> decodeMnemonicCode(byte[] mnemonicCode) throws UnreadableWalletException {
        String code = null;
        try {
            code = new String(mnemonicCode, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new UnreadableWalletException(e.toString());
        }
        return Splitter.on(" ").splitToList(code);
    }
}
