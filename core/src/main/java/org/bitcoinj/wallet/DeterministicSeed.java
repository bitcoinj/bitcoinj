/*
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

package org.bitcoinj.wallet;

import com.google.common.base.MoreObjects;
import org.bitcoinj.base.internal.TimeUtils;
import org.bitcoinj.base.internal.InternalUtils;
import org.bitcoinj.crypto.AesKey;
import org.bitcoinj.crypto.EncryptableItem;
import org.bitcoinj.crypto.EncryptedData;
import org.bitcoinj.crypto.KeyCrypter;
import org.bitcoinj.crypto.MnemonicCode;
import org.bitcoinj.crypto.MnemonicException;

import javax.annotation.Nullable;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.protobuf.wallet.Protos;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;
import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * Holds the seed bytes for the BIP32 deterministic wallet algorithm, inside a
 * {@link DeterministicKeyChain}. The purpose of this wrapper is to simplify the encryption
 * code.
 */
public class DeterministicSeed implements EncryptableItem {
    // It would take more than 10^12 years to brute-force a 128 bit seed using $1B worth of computing equipment.
    public static final int DEFAULT_SEED_ENTROPY_BITS = 128;
    public static final int MAX_SEED_ENTROPY_BITS = 512;

    @Nullable private final byte[] seed;
    @Nullable private final List<String> mnemonicCode; // only one of mnemonicCode/encryptedMnemonicCode will be set
    @Nullable private final EncryptedData encryptedMnemonicCode;
    @Nullable private final EncryptedData encryptedSeed;
    // Creation time of the seed, or null if the seed was deserialized from a version that did not have this field.
    @Nullable private Instant creationTime = null;

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link MnemonicCode} for more
     * details on this scheme.
     * @param mnemonicCode list of words, space separated
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     * @param creationTime when the seed was originally created
     */
    public static DeterministicSeed ofMnemonic(String mnemonicCode, String passphrase, Instant creationTime) {
        return new DeterministicSeed(mnemonicCode, null, passphrase, Objects.requireNonNull(creationTime));
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link MnemonicCode} for more
     * details on this scheme. Use this if you don't know the seed's creation time.
     * @param mnemonicCode list of words, space separated
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     */
    public static DeterministicSeed ofMnemonic(String mnemonicCode, String passphrase) {
        return new DeterministicSeed(mnemonicCode, null, passphrase, null);
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link MnemonicCode} for more
     * details on this scheme.
     * @param mnemonicCode list of words
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     * @param creationTime when the seed was originally created
     */
    public static DeterministicSeed ofMnemonic(List<String> mnemonicCode, String passphrase, Instant creationTime) {
        return new DeterministicSeed(mnemonicCode, null, passphrase, Objects.requireNonNull(creationTime));
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link MnemonicCode} for more
     * details on this scheme. Use this if you don't know the seed's creation time.
     * @param mnemonicCode list of words
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     */
    public static DeterministicSeed ofMnemonic(List<String> mnemonicCode, String passphrase) {
        return new DeterministicSeed(mnemonicCode, null, passphrase, null);
    }

    /**
     * Constructs a BIP 39 mnemonic code and a seed from a given entropy. See {@link MnemonicCode} for more
     * details on this scheme.
     * @param entropy entropy bits, length must be at least 128 bits and a multiple of 32 bits
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     * @param creationTime when the seed was originally created
     */
    public static DeterministicSeed ofEntropy(byte[] entropy, String passphrase, Instant creationTime) {
        return new DeterministicSeed(entropy, passphrase, Objects.requireNonNull(creationTime));
    }

    /**
     * Constructs a BIP 39 mnemonic code and a seed from a given entropy. See {@link MnemonicCode} for more
     * details on this scheme. Use this if you don't know the seed's creation time.
     * @param entropy entropy bits, length must be at least 128 bits and a multiple of 32 bits
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     */
    public static DeterministicSeed ofEntropy(byte[] entropy, String passphrase) {
        return new DeterministicSeed(entropy, passphrase, null);
    }

    /**
     * Constructs a BIP 39 mnemonic code and a seed randomly. See {@link MnemonicCode} for more
     * details on this scheme.
     * @param random random source for the entropy
     * @param bits number of bits of entropy, must be at least 128 bits and a multiple of 32 bits
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     */
    public static DeterministicSeed ofRandom(SecureRandom random, int bits, String passphrase) {
        return new DeterministicSeed(random, bits, passphrase);
    }

    /**
     * Internal use only – will be restricted to private in a future release.
     * Use {@link #ofMnemonic(String, String, Instant)} or {@link #ofMnemonic(String, String)}  instead.
     */
    DeterministicSeed(String mnemonicString, byte[] seed, String passphrase, @Nullable Instant creationTime) {
        this(decodeMnemonicCode(mnemonicString), seed, passphrase, creationTime);
    }

    /** @deprecated use {@link #ofMnemonic(String, String, Instant)} or {@link #ofMnemonic(String, String)} */
    @Deprecated
    public DeterministicSeed(String mnemonicString, byte[] seed, String passphrase, long creationTimeSecs) {
        this(mnemonicString, seed, passphrase, creationTimeSecs > 0 ? Instant.ofEpochSecond(creationTimeSecs) : null);
    }

    /** Internal use only. */
    private DeterministicSeed(byte[] seed, List<String> mnemonic, @Nullable Instant creationTime) {
        this.seed = Objects.requireNonNull(seed);
        this.mnemonicCode = Objects.requireNonNull(mnemonic);
        this.encryptedMnemonicCode = null;
        this.encryptedSeed = null;
        this.creationTime = creationTime;
    }

    /** Internal use only – will be restricted to private in a future release. */
    DeterministicSeed(EncryptedData encryptedMnemonic, @Nullable EncryptedData encryptedSeed, @Nullable Instant creationTime) {
        this.seed = null;
        this.mnemonicCode = null;
        this.encryptedMnemonicCode = Objects.requireNonNull(encryptedMnemonic);
        this.encryptedSeed = encryptedSeed;
        this.creationTime = creationTime;
    }

    /** @deprecated will be removed in a future release */
    @Deprecated
    public DeterministicSeed(EncryptedData encryptedMnemonic, @Nullable EncryptedData encryptedSeed, long creationTimeSecs) {
        this(encryptedMnemonic, encryptedSeed, creationTimeSecs > 0 ? Instant.ofEpochSecond(creationTimeSecs) : null);
    }

    /** Internal use only. */
    private DeterministicSeed(List<String> mnemonicCode, @Nullable byte[] seed, String passphrase, @Nullable Instant creationTime) {
        this((seed != null ? seed : MnemonicCode.toSeed(mnemonicCode, Objects.requireNonNull(passphrase))), mnemonicCode, creationTime);
    }

    /** @deprecated use {@link #ofMnemonic(List, String, Instant)} or {@link #ofMnemonic(List, String)} */
    @Deprecated
    public DeterministicSeed(List<String> mnemonicCode, @Nullable byte[] seed, String passphrase, long creationTimeSecs) {
        this(mnemonicCode, seed, passphrase, creationTimeSecs > 0 ? Instant.ofEpochSecond(creationTimeSecs) : null);
    }

    /** @deprecated use {@link #ofRandom(SecureRandom, int, String)} */
    @Deprecated
    public DeterministicSeed(SecureRandom random, int bits, String passphrase) {
        this(getEntropy(random, bits), Objects.requireNonNull(passphrase), TimeUtils.currentTime().truncatedTo(ChronoUnit.SECONDS));
    }

    /** Internal use only. */
    private DeterministicSeed(byte[] entropy, String passphrase, @Nullable Instant creationTime) {
        checkArgument(entropy.length * 8 >= DEFAULT_SEED_ENTROPY_BITS, () -> "entropy size too small");
        Objects.requireNonNull(passphrase);

        this.mnemonicCode = MnemonicCode.INSTANCE.toMnemonic(entropy);
        this.seed = MnemonicCode.toSeed(mnemonicCode, passphrase);
        this.encryptedMnemonicCode = null;
        this.encryptedSeed = null;
        this.creationTime = creationTime;
    }

    /** @deprecated use {@link #ofEntropy(byte[], String, Instant)} or {@link #ofEntropy(byte[], String)} */
    @Deprecated
    public DeterministicSeed(byte[] entropy, String passphrase, long creationTimeSecs) {
        this(entropy, passphrase, creationTimeSecs > 0 ? Instant.ofEpochSecond(creationTimeSecs) : null);
    }

    private static byte[] getEntropy(SecureRandom random, int bits) {
        checkArgument(bits <= MAX_SEED_ENTROPY_BITS, () ->
                "requested entropy size too large");

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
        return toString(false);
    }

    public String toString(boolean includePrivate) {
        MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this).omitNullValues();
        if (isEncrypted())
            helper.addValue("encrypted");
        else if (includePrivate)
            helper.addValue(toHexString()).add("mnemonicCode", getMnemonicString());
        else
            helper.addValue("unencrypted");
        return helper.toString();
    }

    /** Returns the seed as hex or null if encrypted. */
    @Nullable
    public String toHexString() {
        return seed != null ? ByteUtils.formatHex(seed) : null;
    }

    @Nullable
    @Override
    public byte[] getSecretBytes() {
        return getMnemonicAsBytes();
    }

    @Nullable
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

    @Nullable
    public EncryptedData getEncryptedSeedData() {
        return encryptedSeed;
    }

    @Override
    public Optional<Instant> getCreationTime() {
        return Optional.ofNullable(creationTime);
    }

    /**
     * Sets the creation time of this seed.
     * @param creationTime creation time of this seed
     */
    public void setCreationTime(Instant creationTime) {
        this.creationTime = Objects.requireNonNull(creationTime);
    }

    /**
     * Clears the creation time of this seed. This is mainly used deserialization and cloning. Normally you should not
     * need to use this, as keys should have proper creation times whenever possible.
     */
    public void clearCreationTime() {
        this.creationTime = null;
    }

    /** @deprecated use {@link #setCreationTime(Instant)} */
    @Deprecated
    public void setCreationTimeSeconds(long creationTimeSecs) {
        if (creationTimeSecs > 0)
            setCreationTime(Instant.ofEpochSecond(creationTimeSecs));
        else if (creationTimeSecs == 0)
            clearCreationTime();
        else
            throw new IllegalArgumentException("Cannot set creation time to negative value: " + creationTimeSecs);
    }

    public DeterministicSeed encrypt(KeyCrypter keyCrypter, AesKey aesKey) {
        checkState(encryptedMnemonicCode == null, () ->
                "trying to encrypt seed twice");
        checkState(mnemonicCode != null, () ->
                "mnemonic missing so cannot encrypt");
        EncryptedData encryptedMnemonic = keyCrypter.encrypt(getMnemonicAsBytes(), aesKey);
        EncryptedData encryptedSeed = keyCrypter.encrypt(seed, aesKey);
        return new DeterministicSeed(encryptedMnemonic, encryptedSeed, creationTime);
    }

    private byte[] getMnemonicAsBytes() {
        return getMnemonicString().getBytes(StandardCharsets.UTF_8);
    }

    public DeterministicSeed decrypt(KeyCrypter crypter, String passphrase, AesKey aesKey) {
        checkState(isEncrypted());
        Objects.requireNonNull(encryptedMnemonicCode);
        List<String> mnemonic = decodeMnemonicCode(crypter.decrypt(encryptedMnemonicCode, aesKey));
        byte[] seed = encryptedSeed == null ? null : crypter.decrypt(encryptedSeed, aesKey);
        return new DeterministicSeed(mnemonic, seed, passphrase, creationTime);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DeterministicSeed other = (DeterministicSeed) o;
        return Objects.equals(creationTime, other.creationTime)
            && Objects.equals(encryptedMnemonicCode, other.encryptedMnemonicCode)
            && Objects.equals(mnemonicCode, other.mnemonicCode);
    }

    @Override
    public int hashCode() {
        return Objects.hash(creationTime, encryptedMnemonicCode, mnemonicCode);
    }

    /**
     * Check if our mnemonic is a valid mnemonic phrase for our word list.
     * Does nothing if we are encrypted.
     *
     * @throws org.bitcoinj.crypto.MnemonicException if check fails
     */
    public void check() throws MnemonicException {
        if (mnemonicCode != null)
            MnemonicCode.INSTANCE.check(mnemonicCode);
    }

    byte[] getEntropyBytes() throws MnemonicException {
        return MnemonicCode.INSTANCE.toEntropy(mnemonicCode);
    }

    /** Get the mnemonic code, or null if unknown. */
    @Nullable
    public List<String> getMnemonicCode() {
        return mnemonicCode;
    }

    /** Get the mnemonic code as string, or null if unknown. */
    @Nullable
    public String getMnemonicString() {
        return mnemonicCode != null ? InternalUtils.SPACE_JOINER.join(mnemonicCode) : null;
    }

    private static List<String> decodeMnemonicCode(byte[] mnemonicCode) {
        return decodeMnemonicCode(new String(mnemonicCode, StandardCharsets.UTF_8));
    }

    private static List<String> decodeMnemonicCode(String mnemonicCode) {
        return InternalUtils.WHITESPACE_SPLITTER.splitToList(mnemonicCode);
    }
}
