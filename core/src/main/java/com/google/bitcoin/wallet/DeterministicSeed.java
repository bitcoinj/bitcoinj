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

    @Nullable private final byte[] seed;
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

    DeterministicSeed(String mnemonicCode, String passphrase, long creationTimeSeconds) throws UnreadableWalletException {
        this(decodeMnemonicCode(mnemonicCode), passphrase, creationTimeSeconds);
    }

    DeterministicSeed(byte[] seed, List<String> mnemonic, long creationTimeSeconds) {
        this.seed = checkNotNull(seed);
        this.mnemonicCode = checkNotNull(mnemonic);
        this.encryptedMnemonicCode = null;
        this.creationTimeSeconds = creationTimeSeconds;
    }

    DeterministicSeed(EncryptedData encryptedMnemonic, long creationTimeSeconds) {
        this.seed = null;
        this.mnemonicCode = null;
        this.encryptedMnemonicCode = checkNotNull(encryptedMnemonic);
        this.creationTimeSeconds = creationTimeSeconds;
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link com.google.bitcoin.crypto.MnemonicCode} for more
     * details on this scheme.
     * @param mnemonicCode A list of words.
     * @param passphrase A user supplied passphrase, or an empty string if there is no passphrase
     * @param creationTimeSeconds When the seed was originally created, UNIX time.
     */
    public DeterministicSeed(List<String> mnemonicCode, String passphrase, long creationTimeSeconds) {
        this(MnemonicCode.toSeed(mnemonicCode, passphrase), mnemonicCode, creationTimeSeconds);
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
        this(getEntropy(random, bits), passphrase, creationTimeSeconds);
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link com.google.bitcoin.crypto.MnemonicCode} for more
     * details on this scheme.
     * @param entropy entropy bits, length must be divisible by 32
     * @param passphrase A user supplied passphrase, or an empty string if there is no passphrase
     * @param creationTimeSeconds When the seed was originally created, UNIX time.
     */
    public DeterministicSeed(byte[] entropy, String passphrase, long creationTimeSeconds) {
        Preconditions.checkArgument(entropy.length % 4 == 0, "entropy size in bits not divisible by 32");
        Preconditions.checkArgument(entropy.length * 8 >= DEFAULT_SEED_ENTROPY_BITS, "entropy size too small");

        try {
            this.mnemonicCode = getCachedMnemonicCodec().toMnemonic(entropy);
        } catch (MnemonicException.MnemonicLengthException e) {
            // cannot happen
            throw new RuntimeException(e);
        }
        this.seed = MnemonicCode.toSeed(mnemonicCode, passphrase);
        this.encryptedMnemonicCode = null;
        this.creationTimeSeconds = creationTimeSeconds;
    }

    private static byte[] getEntropy(SecureRandom random, int bits) {
        Preconditions.checkArgument(bits <= MAX_SEED_ENTROPY_BITS, "requested entropy size too large");

        byte[] seed = new byte[bits / 8];
        random.nextBytes(seed);
        return seed;
    }

    @Override
    public boolean isEncrypted() {
        checkState(mnemonicCode != null || encryptedMnemonicCode != null);
        return encryptedMnemonicCode != null;
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
        if (seed != null)
            return HEX.encode(seed);
        else
            return null;
    }

    @Nullable
    @Override
    public byte[] getSecretBytes() {
        return getMnemonicAsBytes();
    }

    public byte[] getSeedBytes() {
        return seed;
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

    public DeterministicSeed encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) {
        checkState(encryptedMnemonicCode == null, "Trying to encrypt seed twice");
        checkState(mnemonicCode != null, "Mnemonic missing so cannot encrypt");
        EncryptedData mnemonic = keyCrypter.encrypt(getMnemonicAsBytes(), aesKey);
        return new DeterministicSeed(mnemonic, creationTimeSeconds);
    }

    private byte[] getMnemonicAsBytes() {
        try {
            return Joiner.on(" ").join(mnemonicCode).getBytes(UTF_8);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public DeterministicSeed decrypt(KeyCrypter crypter, String passphrase, KeyParameter aesKey) {
        checkState(isEncrypted());
        checkNotNull(encryptedMnemonicCode);
        List<String> mnemonic = null;
        try {
            mnemonic = decodeMnemonicCode(crypter.decrypt(encryptedMnemonicCode, aesKey));
        } catch (UnreadableWalletException e) {
            // TODO what is the best way to handle this exception?
            throw new RuntimeException(e);
        }
        return new DeterministicSeed(mnemonic, passphrase, creationTimeSeconds);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        DeterministicSeed seed = (DeterministicSeed) o;

        if (creationTimeSeconds != seed.creationTimeSeconds) return false;
        if (encryptedMnemonicCode != null) {
            if (seed.encryptedMnemonicCode == null) return false;
            if (!encryptedMnemonicCode.equals(seed.encryptedMnemonicCode)) return false;
        } else {
            if (!mnemonicCode.equals(seed.mnemonicCode)) return false;
        }

        return true;
    }

    @Override
    public int hashCode() {
        int result = encryptedMnemonicCode != null ? encryptedMnemonicCode.hashCode() : mnemonicCode.hashCode();
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

    byte[] getEntropyBytes() throws MnemonicException {
        return getCachedMnemonicCodec().toEntropy(mnemonicCode);
    }

    /** Get the mnemonic code, or null if unknown. */
    @Nullable
    public List<String> getMnemonicCode() {
        return mnemonicCode;
    }

    private static List<String> decodeMnemonicCode(byte[] mnemonicCode) throws UnreadableWalletException {
        String code = null;
        try {
            code = new String(mnemonicCode, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new UnreadableWalletException(e.toString());
        }
        return Splitter.on(" ").splitToList(code);
    }

    private static List<String> decodeMnemonicCode(String mnemonicCode) {
        return Splitter.on(" ").splitToList(mnemonicCode);
    }
}
