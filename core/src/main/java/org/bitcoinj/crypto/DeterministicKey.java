/*
 * Copyright 2013 Matija Mazi.
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

package org.bitcoinj.crypto;

import com.google.common.base.MoreObjects;
import com.google.common.primitives.UnsignedBytes;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.ScriptType;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.base.Base58;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.crypto.internal.CryptoUtils;
import org.bouncycastle.math.ec.ECPoint;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static org.bitcoinj.base.internal.Preconditions.checkArgument;
import static org.bitcoinj.base.internal.Preconditions.checkState;

/**
 * A deterministic key is a node in a {@link DeterministicHierarchy}. As per
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">the BIP 32 specification</a> it is a pair
 * (key, chaincode). If you know its path in the tree and its chain code you can derive more keys from this. To obtain
 * one of these, you can call {@link HDKeyDerivation#createMasterPrivateKey(byte[])}.
 */
public class DeterministicKey extends ECKey {

    /** Sorts deterministic keys in the order of their child number. That's <i>usually</i> the order used to derive them. */
    public static final Comparator<ECKey> CHILDNUM_ORDER = (k1, k2) -> {
        ChildNumber cn1 = ((DeterministicKey) k1).getChildNumber();
        ChildNumber cn2 = ((DeterministicKey) k2).getChildNumber();
        return cn1.compareTo(cn2);
    };

    @Nullable
    private final DeterministicKey parent;
    private final HDPath.HDPartialPath childNumberPath;
    private final int depth;
    private final int parentFingerprint; // 0 if this key is root node of key hierarchy

    /** 32 bytes */
    private final byte[] chainCode;

    /** Constructs a key from its components. This is not normally something you should use. */
    public DeterministicKey(List<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            LazyECPoint publicAsPoint,
                            @Nullable BigInteger priv,
                            @Nullable DeterministicKey parent) {
        this(priv, publicAsPoint.compress(), parent == null ? 0 : parent.depth + 1, parent,
                parent != null ? parent.getFingerprint() : 0, chainCode, HDPath.M(childNumberPath), null, null);
    }

    public DeterministicKey(List<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            ECPoint publicAsPoint,
                            boolean compressed,
                            @Nullable BigInteger priv,
                            @Nullable DeterministicKey parent) {
        this(childNumberPath, chainCode, new LazyECPoint(publicAsPoint, compressed), priv, parent);
    }

    /** Constructs a key from its components. This is not normally something you should use. */
    public DeterministicKey(HDPath hdPath,
                            byte[] chainCode,
                            BigInteger priv,
                            @Nullable DeterministicKey parent) {
        this(priv, new LazyECPoint(ECKey.publicPointFromPrivate(priv), true), parent == null ? 0 : parent.depth + 1,
                parent, parent != null ? parent.getFingerprint() : 0, chainCode, hdPath, null, null);
    }

    /** Constructs a key from its components. This is not normally something you should use. */
    public DeterministicKey(List<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            KeyCrypter crypter,
                            LazyECPoint pub,
                            EncryptedData encryptedPrivateKey,
                            @Nullable DeterministicKey parent) {
        this(null, pub.compress(), parent == null ? 0 : parent.depth + 1, parent,
                parent != null ? parent.getFingerprint() : 0, chainCode, HDPath.M(childNumberPath),
                Objects.requireNonNull(encryptedPrivateKey), Objects.requireNonNull(crypter));
    }

    /**
     * Return the fingerprint of a key's parent as an int value, or zero if the key is the
     * root node of the key hierarchy.  Raise an exception if the arguments are inconsistent.
     * This method exists to avoid code repetition in the constructors.
     */
    private static int ascertainParentFingerprint(@Nullable DeterministicKey parent, int parentFingerprint) throws IllegalArgumentException {
        if (parentFingerprint != 0) {
            if (parent != null)
                checkArgument(parent.getFingerprint() == parentFingerprint, () ->
                        "parent fingerprint mismatch: " + Integer.toHexString(parent.getFingerprint()) + " vs " + Integer.toHexString(parentFingerprint));
            return parentFingerprint;
        } else return 0;
    }

    /**
     * Constructs a key from its components, including its public key data and possibly-redundant
     * information about its parent key.  Invoked when deserializing, but otherwise not something that
     * you normally should use.
     */
    public DeterministicKey(List<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            LazyECPoint publicAsPoint,
                            @Nullable DeterministicKey parent,
                            int depth,
                            int parentFingerprint) {
        this(null, publicAsPoint.compress(), depth, parent, parentFingerprint, chainCode, HDPath.M(childNumberPath),
                null, null);
    }

    /**
     * Constructs a key from its components, including its private key data and possibly-redundant
     * information about its parent key.  Invoked when deserializing, but otherwise not something that
     * you normally should use.
     */
    public DeterministicKey(List<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            BigInteger priv,
                            @Nullable DeterministicKey parent,
                            int depth,
                            int parentFingerprint) {
        this(priv, new LazyECPoint(ECKey.publicPointFromPrivate(priv), true), depth, parent, parentFingerprint,
                chainCode, HDPath.M(childNumberPath), null, null);
    }

    /** @deprecated use {@link #withParent(DeterministicKey)} */
    @Deprecated
    public DeterministicKey(DeterministicKey keyToClone, DeterministicKey newParent) {
        this(keyToClone.priv, keyToClone.pub, keyToClone.childNumberPath.size(), newParent,
                newParent.getFingerprint(), keyToClone.chainCode, keyToClone.childNumberPath, null, null);
    }

    /**
     * Canonical constructor.
     * <p>
     * Note on keys with an unusually large depth: due to a restriction of the serialization format, keys with a depth
     * greater than 255 cannot be serialized to Base58. This affects methods {@link #serializePubB58(Network)} and
     * {@link #serializePrivB58(Network)}, but not ProtoBuf-serialization or key derivation in itself.
     *
     * @param priv                private key, or {@code null} if public key only
     * @param pub                 public key, corresponding to private key (if present)
     * @param depth               depth of this key in the path, {@code 0} means master key
     * @param parent              parent deterministic key, or {@code null} if unknown or this is master key
     * @param parentFingerprint   4 byte fingerprint of parent key, or {0} if parent unknown or this is master key
     * @param chainCode           32 bytes of chain code
     * @param hdPath              path leading up to this key
     * @param encryptedPrivateKey private key in encrypted form
     * @param keyCrypter          crypter to use for decrypting the private key
     */
    private DeterministicKey(@Nullable BigInteger priv, LazyECPoint pub, int depth, @Nullable DeterministicKey parent,
                             int parentFingerprint, byte[] chainCode, HDPath hdPath,
                             @Nullable EncryptedData encryptedPrivateKey, @Nullable KeyCrypter keyCrypter) {
        super(priv, pub);
        checkArgument(chainCode.length == 32);
        checkArgument(priv == null || encryptedPrivateKey == null, () ->
                "priv and encryptedPrivateKey can't be set together");
        checkArgument((encryptedPrivateKey == null) == (keyCrypter == null), () ->
                "encryptedPrivateKey and keyCrypter must be set together");
        this.depth = depth;
        this.parent = parent;
        this.parentFingerprint = ascertainParentFingerprint(parent, parentFingerprint);
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.childNumberPath = Objects.requireNonNull(hdPath).asPartial();
        this.encryptedPrivateKey = encryptedPrivateKey;
        this.keyCrypter = keyCrypter;
    }

    /**
     * Returns the {@link HDPath.HDFullPath} through the {@link DeterministicHierarchy} to this key's position in the tree.
     * A path can be written as {@code M/0/1/0} which means the first child of the root, the second child of that node, then
     * the first child of that node.
     * @return A full path starting with {@code 'm'} or {@code 'M'} depending upon whether ths private key is available.
     */
    public HDPath.HDFullPath getPath() {
        return childNumberPath.asFull(prefix());
    }

    /**
     * @return The prefix {@code 'm'} or {@code 'M'} for this key's HD path.
     */
    private HDPath.Prefix prefix() {
        return isWatching() ? HDPath.Prefix.PUBLIC : HDPath.Prefix.PRIVATE;
    }

    /**
     * Returns the path of this key as a human-readable string starting with M or m to indicate the master key.
     */
    public String getPathAsString() {
        return getPath().toString();
    }

    /**
     * Return this key's depth in the hierarchy, where the root node is at depth zero.
     * This may be different than the number of segments in the path if this key was
     * deserialized without access to its parent.
     */
    public int getDepth() {
        return depth;
    }

    /** Returns the last element of the path returned by {@link DeterministicKey#getPath()} */
    public ChildNumber getChildNumber() {
        return childNumberPath.size() == 0 ? ChildNumber.ZERO : childNumberPath.get(childNumberPath.size() - 1);
    }

    /**
     * Returns the chain code associated with this key. See the specification to learn more about chain codes.
     */
    public byte[] getChainCode() {
        return chainCode;
    }

    /**
     * Returns RIPE-MD160(SHA256(pub key bytes)).
     */
    public byte[] getIdentifier() {
        return CryptoUtils.sha256hash160(getPubKey());
    }

    /** Returns the first 32 bits of the result of {@link #getIdentifier()}. */
    public int getFingerprint() {
        // TODO: why is this different than armory's fingerprint? BIP 32: "The first 32 bits of the identifier are called the fingerprint."
        return ByteBuffer.wrap(Arrays.copyOfRange(getIdentifier(), 0, 4)).getInt();
    }

    @Nullable
    public DeterministicKey getParent() {
        return parent;
    }

    /**
     * Return the fingerprint of the key from which this key was derived, if this is a
     * child key, or else an array of four zero-value bytes.
     */
    public int getParentFingerprint() {
        return parentFingerprint;
    }

    /**
     * Returns private key bytes, padded with zeros to 33 bytes.
     * @throws java.lang.IllegalStateException if the private key bytes are missing.
     */
    public byte[] getPrivKeyBytes33() {
        byte[] bytes33 = new byte[33];
        byte[] priv = getPrivKeyBytes();
        System.arraycopy(priv, 0, bytes33, 33 - priv.length, priv.length);
        return bytes33;
    }

    /**
     * Returns the same key with the private keys (cleartext and encrypted) removed. May return the same instance.
     * <p>
     * The purpose of this is to save
     * memory: the private key can always be very efficiently rederived from a parent that a private key, so storing
     * all the private keys in RAM is a poor tradeoff especially on constrained devices. This means that the returned
     * key may still be usable for signing and so on, so don't expect it to be a true pubkey-only object! If you want
     * that then you should follow this call with a call to {@link #withoutParent()}.
     *
     * @return this key without private key
     */
    public DeterministicKey withoutPrivateKey() {
        return priv == null && encryptedPrivateKey == null && keyCrypter == null ?
                this :
                new DeterministicKey(null, pub, depth, parent, parentFingerprint, chainCode, childNumberPath,
                        null, null);
    }

    /** @deprecated use {@link #withoutPrivateKey()} */
    @Deprecated
    public DeterministicKey dropPrivateBytes() {
        return withoutPrivateKey();
    }

    /**
     * Returns the same key with another parent and parent fingerprint. The depth is derived from the parent by
     * incrementing.
     *
     * @param parent new parent
     * @return key with another parent, parent fingerprint and depth derived from parent
     */
    public DeterministicKey withParent(DeterministicKey parent) {
        Objects.requireNonNull(parent);
        return new DeterministicKey(this.priv, this.pub, parent.getDepth() + 1, parent, parent.getFingerprint(),
                this.chainCode, this.childNumberPath, this.encryptedPrivateKey, this.keyCrypter);
    }

    /**
     * Returns the same key with the parent pointer removed. It still knows its own path and the parent fingerprint.
     * <p>
     * If this key doesn't have private key bytes stored/cached itself, but could rederive them from the parent, then
     * the new key returned by this method won't be able to do that. Thus, using withoutPrivateKey().withoutParent() on a
     * regular DeterministicKey will yield a new DeterministicKey that cannot sign or do other things involving the
     * private key at all.
     *
     * @return this key without parent pointer
     */
    public DeterministicKey withoutParent() {
        return new DeterministicKey(priv, pub, depth, null, parentFingerprint, chainCode, childNumberPath,
                encryptedPrivateKey, keyCrypter);
    }

    /** @deprecated use {@link #withoutParent()} */
    @Deprecated
    public DeterministicKey dropParent() {
        return withoutParent();
    }

    static byte[] addChecksum(byte[] input) {
        int inputLength = input.length;
        byte[] checksummed = new byte[inputLength + 4];
        System.arraycopy(input, 0, checksummed, 0, inputLength);
        byte[] checksum = Sha256Hash.hashTwice(input);
        System.arraycopy(checksum, 0, checksummed, inputLength, 4);
        return checksummed;
    }

    @Override
    public DeterministicKey encrypt(KeyCrypter keyCrypter, AesKey aesKey) throws KeyCrypterException {
        throw new UnsupportedOperationException("Must supply a new parent for encryption");
    }

    public DeterministicKey encrypt(KeyCrypter keyCrypter, AesKey aesKey, @Nullable DeterministicKey newParent) throws KeyCrypterException {
        // Same as the parent code, except we construct a DeterministicKey instead of an ECKey.
        Objects.requireNonNull(keyCrypter);
        if (newParent != null)
            checkArgument(newParent.isEncrypted());
        final byte[] privKeyBytes = getPrivKeyBytes();
        checkState(privKeyBytes != null, () -> "Private key is not available");
        EncryptedData encryptedPrivateKey = keyCrypter.encrypt(privKeyBytes, aesKey);
        DeterministicKey key = new DeterministicKey(childNumberPath, chainCode, keyCrypter, pub, encryptedPrivateKey, newParent);
        if (newParent == null) {
            Optional<Instant> creationTime = this.getCreationTime();
            if (creationTime.isPresent())
                key.setCreationTime(creationTime.get());
            else
                key.clearCreationTime();
        }
        return key;
    }

    /**
     * A deterministic key is considered to be 'public key only' if it hasn't got a private key part and it cannot be
     * rederived. If the hierarchy is encrypted this returns true.
     */
    @Override
    public boolean isPubKeyOnly() {
        return super.isPubKeyOnly() && (parent == null || parent.isPubKeyOnly());
    }

    @Override
    public boolean hasPrivKey() {
        return findParentWithPrivKey() != null;
    }

    @Nullable
    @Override
    public byte[] getSecretBytes() {
        return priv != null ? getPrivKeyBytes() : null;
    }

    /**
     * A deterministic key is considered to be encrypted if it has access to encrypted private key bytes, OR if its
     * parent does. The reason is because the parent would be encrypted under the same key and this key knows how to
     * rederive its own private key bytes from the parent, if needed.
     */
    @Override
    public boolean isEncrypted() {
        return priv == null && (super.isEncrypted() || (parent != null && parent.isEncrypted()));
    }

    /**
     * Returns this keys {@link KeyCrypter} <b>or</b> the keycrypter of its parent key.
     */
    @Override @Nullable
    public KeyCrypter getKeyCrypter() {
        if (keyCrypter != null)
            return keyCrypter;
        else if (parent != null)
            return parent.getKeyCrypter();
        else
            return null;
    }

    @Override
    public ECDSASignature sign(Sha256Hash input, @Nullable AesKey aesKey) throws KeyCrypterException {
        if (isEncrypted()) {
            // If the key is encrypted, ECKey.sign will decrypt it first before rerunning sign. Decryption walks the
            // key hierarchy to find the private key (see below), so, we can just run the inherited method.
            return super.sign(input, aesKey);
        } else {
            // If it's not encrypted, derive the private via the parents.
            final BigInteger privateKey = findOrDerivePrivateKey();
            if (privateKey == null) {
                // This key is a part of a public-key only hierarchy and cannot be used for signing
                throw new MissingPrivateKeyException();
            }
            return super.doSign(input, privateKey);
        }
    }

    @Override
    public DeterministicKey decrypt(KeyCrypter keyCrypter, AesKey aesKey) throws KeyCrypterException {
        Objects.requireNonNull(keyCrypter);
        // Check that the keyCrypter matches the one used to encrypt the keys, if set.
        if (this.keyCrypter != null && !this.keyCrypter.equals(keyCrypter))
            throw new KeyCrypterException("The keyCrypter being used to decrypt the key is different to the one that was used to encrypt it");
        BigInteger privKey = findOrDeriveEncryptedPrivateKey(keyCrypter, aesKey);
        DeterministicKey key = new DeterministicKey(childNumberPath, chainCode, privKey, parent);
        if (!Arrays.equals(key.getPubKey(), getPubKey()))
            throw new KeyCrypterException.PublicPrivateMismatch("Provided AES key is wrong");
        if (parent == null) {
            Optional<Instant> creationTime = this.getCreationTime();
            if (creationTime.isPresent())
                key.setCreationTime(creationTime.get());
            else
                key.clearCreationTime();
        }
        return key;
    }

    @Override
    public DeterministicKey decrypt(AesKey aesKey) throws KeyCrypterException {
        return (DeterministicKey) super.decrypt(aesKey);
    }

    // For when a key is encrypted, either decrypt our encrypted private key bytes, or work up the tree asking parents
    // to decrypt and re-derive.
    private BigInteger findOrDeriveEncryptedPrivateKey(KeyCrypter keyCrypter, AesKey aesKey) {
        if (encryptedPrivateKey != null) {
            byte[] decryptedKey = keyCrypter.decrypt(encryptedPrivateKey, aesKey);
            if (decryptedKey.length != 32)
                throw new KeyCrypterException.InvalidCipherText(
                        "Decrypted key must be 32 bytes long, but is " + decryptedKey.length);
            return ByteUtils.bytesToBigInteger(decryptedKey);
        }
        // Otherwise we don't have it, but maybe we can figure it out from our parents. Walk up the tree looking for
        // the first key that has some encrypted private key data.
        DeterministicKey cursor = parent;
        while (cursor != null) {
            if (cursor.encryptedPrivateKey != null) break;
            cursor = cursor.parent;
        }
        if (cursor == null)
            throw new KeyCrypterException("Neither this key nor its parents have an encrypted private key");
        byte[] parentalPrivateKeyBytes = keyCrypter.decrypt(cursor.encryptedPrivateKey, aesKey);
        if (parentalPrivateKeyBytes.length != 32)
            throw new KeyCrypterException.InvalidCipherText(
                    "Decrypted key must be 32 bytes long, but is " + parentalPrivateKeyBytes.length);
        return derivePrivateKeyDownwards(cursor, parentalPrivateKeyBytes);
    }

    private DeterministicKey findParentWithPrivKey() {
        DeterministicKey cursor = this;
        while (cursor != null) {
            if (cursor.priv != null) break;
            cursor = cursor.parent;
        }
        return cursor;
    }

    @Nullable
    private BigInteger findOrDerivePrivateKey() {
        DeterministicKey cursor = findParentWithPrivKey();
        if (cursor == null)
            return null;
        return derivePrivateKeyDownwards(cursor, cursor.priv.toByteArray());
    }

    private BigInteger derivePrivateKeyDownwards(DeterministicKey cursor, byte[] parentalPrivateKeyBytes) {
        DeterministicKey downCursor = new DeterministicKey(cursor.childNumberPath, cursor.chainCode,
                cursor.pub, ByteUtils.bytesToBigInteger(parentalPrivateKeyBytes), cursor.parent);
        // Now we have to re-derive the keys along the path back to ourselves. That path can be found by just truncating
        // our path with the length of the parent's path.
        List<ChildNumber> path = childNumberPath.list().subList(cursor.getPath().size(), childNumberPath.size());
        for (ChildNumber num : path) {
            downCursor = HDKeyDerivation.deriveChildKey(downCursor, num);
        }
        // downCursor is now the same key as us, but with private key bytes.
        // If it's not, it means we tried decrypting with an invalid password and earlier checks e.g. for padding didn't
        // catch it.
        if (!downCursor.pub.equals(pub))
            throw new KeyCrypterException.PublicPrivateMismatch("Could not decrypt bytes");
        return Objects.requireNonNull(downCursor.priv);
    }

    /**
     * Derives a child at the given index using hardened derivation.  Note: {@code index} is
     * not the "i" value.  If you want the softened derivation, then use instead
     * {@code HDKeyDerivation.deriveChildKey(this, new ChildNumber(child, false))}.
     */
    public DeterministicKey derive(int child) {
        return HDKeyDerivation.deriveChildKey(this, new ChildNumber(child, true));
    }

    /**
     * Returns the private key of this deterministic key. Even if this object isn't storing the private key,
     * it can be re-derived by walking up to the parents if necessary and this is what will happen.
     * @throws java.lang.IllegalStateException if the parents are encrypted or a watching chain.
     */
    @Override
    public BigInteger getPrivKey() {
        final BigInteger key = findOrDerivePrivateKey();
        checkState(key != null, () ->
                "private key bytes not available");
        return key;
    }

    // For testing only
    byte[] serialize(Network network, boolean pub) {
        return serialize(network, pub, ScriptType.P2PKH);
    }

    // TODO: remove outputScriptType parameter and merge with the two-param serialize() method. When deprecated serializePubB58/serializePrivB58 methods are removed.
    private byte[] serialize(Network network, boolean pub, ScriptType outputScriptType) {
        // TODO: Remove use of NetworkParameters after we can get BIP32 headers from Network enum
        NetworkParameters params = NetworkParameters.of(network);
        ByteBuffer ser = ByteBuffer.allocate(78);
        if (outputScriptType == ScriptType.P2PKH)
            ser.putInt(pub ? params.getBip32HeaderP2PKHpub() : params.getBip32HeaderP2PKHpriv());
        else if (outputScriptType == ScriptType.P2WPKH)
            ser.putInt(pub ? params.getBip32HeaderP2WPKHpub() : params.getBip32HeaderP2WPKHpriv());
        else
            throw new IllegalStateException(outputScriptType.toString());
        ser.put(UnsignedBytes.checkedCast(getDepth()));
        ser.putInt(getParentFingerprint());
        ser.putInt(getChildNumber().i());
        ser.put(getChainCode());
        ser.put(pub ? getPubKey() : getPrivKeyBytes33());
        checkState(ser.position() == 78);
        return ser.array();
    }

    /**
     * Serialize public key to Base58
     * <p>
     * outputScriptType should not be used in generating "xpub" format. (and "ypub", "zpub", etc. should not be used)
     * @param network which network to serialize key for
     * @param outputScriptType output script type
     * @return the key serialized as a Base58 address
     * @see <a href="https://bitcoin.stackexchange.com/questions/89261/why-does-importmulti-not-support-zpub-and-ypub/89281#89281">Why does importmulti not support zpub and ypub?</a>
     * @deprecated Use a {@link #serializePubB58(Network)} or a descriptor if you need output type information
     */
    public String serializePubB58(Network network, ScriptType outputScriptType) {
        return toBase58(serialize(network, true, outputScriptType));
    }

    /**
     * Serialize private key to Base58
     * <p>
     * outputScriptType should not be used in generating "xprv" format. (and "zprv", "vprv", etc. should not be used)
     * @param network which network to serialize key for
     * @param outputScriptType output script type
     * @return the key serialized as a Base58 address
     * @see <a href="https://bitcoin.stackexchange.com/questions/89261/why-does-importmulti-not-support-zpub-and-ypub/89281#89281">Why does importmulti not support zpub and ypub?</a>
     * @deprecated Use a {@link #serializePrivB58(Network)} or a descriptor if you need output type information
     */
    public String serializePrivB58(Network network, ScriptType outputScriptType) {
        return toBase58(serialize(network, false, outputScriptType));
    }

    /**
     * Serialize public key to Base58 (either "xpub" or "tpub")
     * @param network which network to serialize key for
     * @return the key serialized as a Base58 address
     */
    public String serializePubB58(Network network) {
        return toBase58(serialize(network, true));
    }

    /**
     * Serialize private key to Base58 (either "xprv" or "tprv")
     * @param network which network to serialize key for
     * @return the key serialized as a Base58 address
     */
    public String serializePrivB58(Network network) {
        return toBase58(serialize(network, false));
    }

    static String toBase58(byte[] ser) {
        return Base58.encode(addChecksum(ser));
    }

    /** Deserialize a base-58-encoded HD Key with no parent */
    public static DeterministicKey deserializeB58(String base58, Network network) {
        return deserializeB58(null, base58, network);
    }

    /**
      * Deserialize a base-58-encoded HD Key.
      *  @param parent The parent node in the given key's deterministic hierarchy.
      *  @throws IllegalArgumentException if the base58 encoded key could not be parsed.
      */
    public static DeterministicKey deserializeB58(@Nullable DeterministicKey parent, String base58, Network network) {
        return deserialize(network, Base58.decodeChecked(base58), parent);
    }

    /**
      * Deserialize an HD Key with no parent
      */
    public static DeterministicKey deserialize(Network network, byte[] serializedKey) {
        return deserialize(network, serializedKey, null);
    }

    /**
      * Deserialize an HD Key.
     * @param parent The parent node in the given key's deterministic hierarchy.
     */
    public static DeterministicKey deserialize(Network network, byte[] serializedKey, @Nullable DeterministicKey parent) {
        ByteBuffer buffer = ByteBuffer.wrap(serializedKey);
        int header = buffer.getInt();
        // TODO: Remove us of NetworkParameters when we can get BIP32 header info from Network
        NetworkParameters params = NetworkParameters.of(network);
        final boolean pub = header == params.getBip32HeaderP2PKHpub() || header == params.getBip32HeaderP2WPKHpub();
        final boolean priv = header == params.getBip32HeaderP2PKHpriv() || header == params.getBip32HeaderP2WPKHpriv();
        if (!(pub || priv))
            throw new IllegalArgumentException("Unknown header bytes: " + toBase58(serializedKey).substring(0, 4));
        int depth = Byte.toUnsignedInt(buffer.get()); // convert signed byte to positive int since depth cannot be negative
        final int parentFingerprint = buffer.getInt();
        final int i = buffer.getInt();
        final ChildNumber childNumber = new ChildNumber(i);
        HDPath path;
        if (parent != null) {
            if (parentFingerprint == 0)
                throw new IllegalArgumentException("Parent was provided but this key doesn't have one");
            if (parent.getFingerprint() != parentFingerprint)
                throw new IllegalArgumentException("Parent fingerprints don't match");
            path = parent.getPath().extend(childNumber);
            if (path.size() != depth)
                throw new IllegalArgumentException("Depth does not match");
        } else {
            if (depth >= 1)
                // We have been given a key that is not a root key, yet we lack the object representing the parent.
                // This can happen when deserializing an account key for a watching wallet.  In this case, we assume that
                // the client wants to conceal the key's position in the hierarchy.  The path is truncated at the
                // parent's node.
                path = HDPath.M(childNumber);
            else path = HDPath.M();
        }
        byte[] chainCode = new byte[32];
        buffer.get(chainCode);
        byte[] data = new byte[33];
        buffer.get(data);
        checkArgument(!buffer.hasRemaining(), () ->
                "found unexpected data in key");
        if (pub) {
            return new DeterministicKey(path, chainCode, new LazyECPoint(data), parent, depth, parentFingerprint);
        } else {
            return new DeterministicKey(path, chainCode, ByteUtils.bytesToBigInteger(data), parent, depth, parentFingerprint);
        }
    }

    /**
     * The creation time of a deterministic key is equal to that of its parent, unless this key is the root of a tree
     * in which case the time is stored alongside the key as per normal, see {@link ECKey#getCreationTime()}.
     */
    @Override
    public Optional<Instant> getCreationTime() {
        if (parent != null)
            return parent.getCreationTime();
        else
            return super.getCreationTime();
    }

    /**
     * The creation time of a deterministic key is equal to that of its parent, unless this key is the root of a tree.
     * Thus, setting the creation time on a leaf is forbidden.
     * @param creationTime creation time of this key
     */
    @Override
    public void setCreationTime(Instant creationTime) {
        if (parent != null)
            throw new IllegalStateException("Creation time can only be set on root keys.");
        else
            super.setCreationTime(creationTime);
    }

    /**
     * Clears the creation time of this key. This is mainly used deserialization and cloning. Normally you should not
     * need to use this, as keys should have proper creation times whenever possible.
     */
    @Override
    public void clearCreationTime() {
        if (parent != null)
            throw new IllegalStateException("Creation time can only be cleared on root keys.");
        else
            super.clearCreationTime();
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

    /**
     * Verifies equality of all fields but NOT the parent pointer (thus the same key derived in two separate hierarchy
     * objects will equal each other.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DeterministicKey other = (DeterministicKey) o;
        return super.equals(other)
                && Arrays.equals(this.chainCode, other.chainCode)
                && Objects.equals(this.childNumberPath, other.childNumberPath)
                && Objects.equals(this.depth, other.depth);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), Arrays.hashCode(chainCode), childNumberPath, depth);
    }

    @Override
    public String toString() {
        final MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this).omitNullValues();
        helper.add("pub", ByteUtils.formatHex(pub.getEncoded()));
        helper.add("chainCode", ByteUtils.formatHex(chainCode));
        helper.add("path", getPathAsString());
        helper.add("depth", depth);
        Optional<Instant> creationTime = this.getCreationTime();
        if (!creationTime.isPresent())
            helper.add("creationTimeSeconds", "unknown");
        else if (parent != null)
            helper.add("creationTimeSeconds", creationTime.get().getEpochSecond() + " (inherited)");
        else
            helper.add("creationTimeSeconds", creationTime.get().getEpochSecond());
        helper.add("isEncrypted", isEncrypted());
        helper.add("isPubKeyOnly", isPubKeyOnly());
        return helper.toString();
    }

    @Override
    public void formatKeyWithAddress(boolean includePrivateKeys, @Nullable AesKey aesKey, StringBuilder builder,
                                     Network network, ScriptType outputScriptType, @Nullable String comment) {
        builder.append("  addr:").append(toAddress(outputScriptType, network).toString());
        builder.append("  hash160:").append(ByteUtils.formatHex(getPubKeyHash()));
        builder.append("  (").append(getPathAsString());
        if (comment != null)
            builder.append(", ").append(comment);
        builder.append(")\n");
        if (includePrivateKeys) {
            builder.append("  ").append(toStringWithPrivate(aesKey, network)).append("\n");
        }
    }
}
