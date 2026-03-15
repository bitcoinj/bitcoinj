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

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.bitcoinj.base.internal.ByteUtils;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;
import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * Holds the seed bytes for the BIP32 deterministic wallet algorithm, inside a
 * {@link DeterministicKeyChain}. The purpose of this wrapper is to simplify the encryption
 * code.
 */
public abstract /* sealed */ class DeterministicSeed implements EncryptableItem {
    // It would take more than 10^12 years to brute-force a 128 bit seed using $1B worth of computing equipment.
    public static final int DEFAULT_SEED_ENTROPY_BITS = 128;
    public static final int MAX_SEED_ENTROPY_BITS = 512;

    // Creation time of the seed, or null if the seed was deserialized from a version that did not have this field.
    @Nullable protected Instant creationTime = null;

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link MnemonicCode} for more
     * details on this scheme.
     * @param mnemonicCode list of words, space separated
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     * @param creationTime when the seed was originally created
     */
    public static DeterministicSeed ofMnemonic(String mnemonicCode, String passphrase, Instant creationTime) {
        return new Unencrypted(seedFromMnemonic(splitMnemonicCode(mnemonicCode), passphrase), splitMnemonicCode(mnemonicCode), Objects.requireNonNull(creationTime));
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link MnemonicCode} for more
     * details on this scheme. Use this if you don't know the seed's creation time.
     * @param mnemonicCode list of words, space separated
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     */
    public static DeterministicSeed ofMnemonic(String mnemonicCode, String passphrase) {
        return new Unencrypted(seedFromMnemonic(splitMnemonicCode(mnemonicCode), passphrase), splitMnemonicCode(mnemonicCode), null);
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link MnemonicCode} for more
     * details on this scheme.
     * @param mnemonicCode list of words
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     * @param creationTime when the seed was originally created
     */
    public static DeterministicSeed ofMnemonic(List<String> mnemonicCode, String passphrase, Instant creationTime) {
        return new Unencrypted(seedFromMnemonic(mnemonicCode, passphrase), mnemonicCode, Objects.requireNonNull(creationTime));
    }

    /**
     * Constructs a seed from a BIP 39 mnemonic code. See {@link MnemonicCode} for more
     * details on this scheme. Use this if you don't know the seed's creation time.
     * @param mnemonicCode list of words
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     */
    public static DeterministicSeed ofMnemonic(List<String> mnemonicCode, String passphrase) {
        return new Unencrypted(seedFromMnemonic(mnemonicCode, passphrase), mnemonicCode, null);
    }

    /**
     * Constructs a BIP 39 mnemonic code and a seed from a given entropy. See {@link MnemonicCode} for more
     * details on this scheme.
     * @param entropy entropy bits, length must be at least 128 bits and a multiple of 32 bits
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     * @param creationTime when the seed was originally created
     */
    public static DeterministicSeed ofEntropy(byte[] entropy, String passphrase, Instant creationTime) {
        return DeterministicSeed.ofEntropyInternal(entropy, passphrase, Objects.requireNonNull(creationTime));
    }

    /**
     * Constructs a BIP 39 mnemonic code and a seed from a given entropy. See {@link MnemonicCode} for more
     * details on this scheme. Use this if you don't know the seed's creation time.
     * @param entropy entropy bits, length must be at least 128 bits and a multiple of 32 bits
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     */
    public static DeterministicSeed ofEntropy(byte[] entropy, String passphrase) {
        return DeterministicSeed.ofEntropyInternal(entropy, passphrase, null);
    }

    private static DeterministicSeed ofEntropyInternal(byte[] entropy, String passphrase, @Nullable Instant creationTime) {
        checkArgument(entropy.length * 8 >= DEFAULT_SEED_ENTROPY_BITS, () -> "entropy size too small");
        Objects.requireNonNull(passphrase);
        List<String> mnemonicCode = MnemonicCode.INSTANCE.toMnemonic(entropy);
        byte[] seed = MnemonicCode.toSeed(mnemonicCode, passphrase);
        return new Unencrypted(seed, mnemonicCode, creationTime);
    }

    /**
     * Constructs a BIP 39 mnemonic code and a seed randomly. See {@link MnemonicCode} for more
     * details on this scheme.
     * @param random random source for the entropy
     * @param bits number of bits of entropy, must be at least 128 bits and a multiple of 32 bits
     * @param passphrase user supplied passphrase, or empty string if there is no passphrase
     */
    public static DeterministicSeed ofRandom(SecureRandom random, int bits, String passphrase) {
        return DeterministicSeed.ofEntropyInternal(getEntropy(random, bits), Objects.requireNonNull(passphrase), TimeUtils.currentTime().truncatedTo(ChronoUnit.SECONDS));
    }

    // For use in DeteministicKeyChain.fromProtobuf() only
    static DeterministicSeed fromProtobuf(String mnemonicString, byte @Nullable [] seed, String passphrase, @Nullable Instant creationTime) {
        return new Unencrypted(optionalSeedFromMnemonic(splitMnemonicCode(mnemonicString), passphrase, seed), splitMnemonicCode(mnemonicString), creationTime);
    }

    // For use in DeteministicKeyChain.fromProtobuf() only
    static DeterministicSeed fromProtobufEncrypted(EncryptedData encryptedMnemonic, @Nullable EncryptedData encryptedSeed, @Nullable Instant creationTime) {
        return new Encrypted(encryptedMnemonic, encryptedSeed, creationTime);
    }

    private DeterministicSeed(@Nullable Instant creationTime) {
        this.creationTime = creationTime;
    }

    private static class Unencrypted extends DeterministicSeed {
        private final byte[] seed;
        private final List<String> mnemonicCode; // only one of mnemonicCode/encryptedMnemonicCode will be set

        // Canonical constructor: both seed and mnemonic sentence are present
        private Unencrypted(byte[] seed, List<String> mnemonic, @Nullable Instant creationTime) {
            super(creationTime);
            this.seed = Objects.requireNonNull(seed);
            this.mnemonicCode = Objects.requireNonNull(mnemonic);
        }

        public byte[] seedBytes() {
            return seed;
        }

        public List<String> mnemonicCode() {
            return mnemonicCode;
        }

        /** Get the mnemonic code as string, or null if unknown. */
        public String mnemonicAsString() {
            return InternalUtils.SPACE_JOINER.join(((Unencrypted) this).mnemonicCode());
        }

        byte[] mnemonicAsBytes() {
            return mnemonicAsString().getBytes(StandardCharsets.UTF_8);
        }

        public Encrypted encrypt(KeyCrypter keyCrypter, AesKey aesKey) {
            EncryptedData encryptedMnemonic = keyCrypter.encrypt(mnemonicAsBytes(), aesKey);
            EncryptedData encryptedSeed = keyCrypter.encrypt(seed, aesKey);
            return new Encrypted(encryptedMnemonic, encryptedSeed, creationTime);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Unencrypted other = (Unencrypted) o;
            return Objects.equals(creationTime, other.creationTime)
                    && Objects.equals(mnemonicCode, other.mnemonicCode);
        }

        @Override
        public int hashCode() {
            return Objects.hash(creationTime, mnemonicCode);
        }
    }

    private static class Encrypted extends DeterministicSeed {
        private final EncryptedData encryptedMnemonicCode;
        @Nullable private final EncryptedData encryptedSeed;

        // Canonical constructor: encrypted mnemonic sentence and optional encrypted seed
        private Encrypted(EncryptedData encryptedMnemonic, @Nullable EncryptedData encryptedSeed, @Nullable Instant creationTime) {
            super(creationTime);
            this.encryptedMnemonicCode = Objects.requireNonNull(encryptedMnemonic);
            this.encryptedSeed = encryptedSeed;
        }

        public EncryptedData encryptedMnemonicData() {
            return encryptedMnemonicCode;
        }

        @Nullable
        public EncryptedData encryptedSeedData() {
            return encryptedSeed;
        }

        public KeyCrypter.EncryptionType encryptionType() {
            return KeyCrypter.EncryptionType.ENCRYPTED_SCRYPT_AES;
        }

        public Unencrypted decrypt(KeyCrypter crypter, String passphrase, AesKey aesKey) {
            List<String> mnemonic = decodeMnemonicCode(crypter.decrypt(encryptedMnemonicCode, aesKey));
            byte[] seed = encryptedSeed != null ? crypter.decrypt(encryptedSeed, aesKey) : null;
            return new Unencrypted(optionalSeedFromMnemonic(mnemonic, passphrase, seed), mnemonic, creationTime);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Encrypted other = (Encrypted) o;
            return Objects.equals(creationTime, other.creationTime)
                    && Objects.equals(encryptedMnemonicCode, other.encryptedMnemonicCode);
        }

        @Override
        public int hashCode() {
            return Objects.hash(creationTime, encryptedMnemonicCode);
        }
    }

    // If seed is null, generate seed from mnemonic and passphrase. Otherwise, return unmodified seed.
    private static byte[] optionalSeedFromMnemonic(List<String> mnemonicCode, String passphrase, byte @Nullable [] seed) {
        return seed != null ? seed : seedFromMnemonic(mnemonicCode, passphrase);
    }

    private static byte[] seedFromMnemonic(List<String> mnemonicCode, String passphrase) {
        return MnemonicCode.toSeed(mnemonicCode, Objects.requireNonNull(passphrase));
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
        return this instanceof Encrypted;
    }

    @Override
    public String toString() {
        return toString(false);
    }

    public String toString(boolean includePrivate) {
        MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this).omitNullValues();
        if (this instanceof Encrypted)
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
        return this instanceof Unencrypted
                ? ByteUtils.formatHex(((Unencrypted) this).seedBytes())
                : null;
    }

    @Override
    public byte @Nullable [] getSecretBytes() {
        return this instanceof Unencrypted
                ? ((Unencrypted) this).mnemonicAsBytes()  // ??
                : null;
    }

    public byte @Nullable [] getSeedBytes() {
        return this instanceof Unencrypted
            ? ((Unencrypted) this).seedBytes()
            : null;
    }

    @Nullable
    @Override
    public EncryptedData getEncryptedData() {
        return this instanceof Encrypted
                ? ((Encrypted) this).encryptedMnemonicData()
                : null;
    }

    @Override
    public KeyCrypter.@NonNull EncryptionType getEncryptionType() {
        return this instanceof Encrypted
                ? ((Encrypted) this).encryptionType()
                : KeyCrypter.EncryptionType.UNENCRYPTED;
    }

    @Nullable
    public EncryptedData getEncryptedSeedData() {
        return this instanceof Encrypted
                ? ((Encrypted) this).encryptedSeedData()
                : null;
    }

    @Override
    @NonNull
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

    public DeterministicSeed encrypt(KeyCrypter keyCrypter, AesKey aesKey) {
        checkState(this instanceof Unencrypted, () ->
                "trying to encrypt seed twice");
        return ((Unencrypted) this).encrypt(keyCrypter, aesKey);
    }

    public DeterministicSeed decrypt(KeyCrypter crypter, String passphrase, AesKey aesKey) {
        checkState(this instanceof Encrypted);
        return ((Encrypted) this).decrypt(crypter, passphrase, aesKey);
    }

    /**
     * Check if our mnemonic is a valid mnemonic phrase for our word list.
     * Does nothing if we are encrypted.
     *
     * @throws org.bitcoinj.crypto.MnemonicException if check fails
     */
    public void check() throws MnemonicException {
        if (this instanceof Unencrypted)
            MnemonicCode.INSTANCE.check(((Unencrypted) this).mnemonicCode);
    }

    byte @Nullable[] getEntropyBytes() throws MnemonicException {
        return (this instanceof Unencrypted)
                ? MnemonicCode.INSTANCE.toEntropy(((Unencrypted) this).mnemonicCode)
                : null;
    }

    /** Get the mnemonic code, or null if unknown. */
    @Nullable
    public List<String> getMnemonicCode() {
        return this instanceof Unencrypted
                ? ((Unencrypted) this).mnemonicCode()
                : null;
    }

    /** Get the mnemonic code as string, or null if unknown. */
    @Nullable
    public String getMnemonicString() {
        return this instanceof Unencrypted
                ? ((Unencrypted) this).mnemonicAsString()
                : null;
    }

    // decode to String from byte[]
    private static List<String> decodeMnemonicCode(byte[] mnemonicCode) {
        return splitMnemonicCode(new String(mnemonicCode, StandardCharsets.UTF_8));
    }

    // Split mnemonic code into List<String>
    private static List<String> splitMnemonicCode(String mnemonicCode) {
        return InternalUtils.WHITESPACE_SPLITTER.splitToList(mnemonicCode);
    }
}
