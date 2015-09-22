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

import org.bitcoinj.core.*;

import com.google.common.base.MoreObjects;
import com.google.common.base.Objects;
import com.google.common.collect.ImmutableList;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.math.ec.ECPoint;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Comparator;

import static org.bitcoinj.core.Utils.HEX;
import static com.google.common.base.Preconditions.*;

/**
 * A deterministic key is a node in a {@link DeterministicHierarchy}. As per
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">the BIP 32 specification</a> it is a pair
 * (key, chaincode). If you know its path in the tree and its chain code you can derive more keys from this. To obtain
 * one of these, you can call {@link HDKeyDerivation#createMasterPrivateKey(byte[])}.
 */
public class DeterministicKey extends ECKey {

    /** Sorts deterministic keys in the order of their child number. That's <i>usually</i> the order used to derive them. */
    public static final Comparator<ECKey> CHILDNUM_ORDER = new Comparator<ECKey>() {
        @Override
        public int compare(ECKey k1, ECKey k2) {
            ChildNumber cn1 = ((DeterministicKey) k1).getChildNumber();
            ChildNumber cn2 = ((DeterministicKey) k2).getChildNumber();
            return cn1.compareTo(cn2);
        }
    };

    private final DeterministicKey parent;
    private final ImmutableList<ChildNumber> childNumberPath;
    private final int depth;
    private int parentFingerprint; // 0 if this key is root node of key hierarchy

    /** 32 bytes */
    private final byte[] chainCode;

    /** Constructs a key from its components. This is not normally something you should use. */
    public DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            LazyECPoint publicAsPoint,
                            @Nullable BigInteger priv,
                            @Nullable DeterministicKey parent) {
        super(priv, compressPoint(checkNotNull(publicAsPoint)));
        checkArgument(chainCode.length == 32);
        this.parent = parent;
        this.childNumberPath = checkNotNull(childNumberPath);
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.depth = parent == null ? 0 : parent.depth + 1;
        this.parentFingerprint = (parent != null) ? parent.getFingerprint() : 0;
    }

    public DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            ECPoint publicAsPoint,
                            @Nullable BigInteger priv,
                            @Nullable DeterministicKey parent) {
        this(childNumberPath, chainCode, new LazyECPoint(publicAsPoint), priv, parent);
    }

    /** Constructs a key from its components. This is not normally something you should use. */
    public DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            BigInteger priv,
                            @Nullable DeterministicKey parent) {
        super(priv, compressPoint(ECKey.publicPointFromPrivate(priv)));
        checkArgument(chainCode.length == 32);
        this.parent = parent;
        this.childNumberPath = checkNotNull(childNumberPath);
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.depth = parent == null ? 0 : parent.depth + 1;
        this.parentFingerprint = (parent != null) ? parent.getFingerprint() : 0;
    }

    /** Constructs a key from its components. This is not normally something you should use. */
    public DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            KeyCrypter crypter,
                            LazyECPoint pub,
                            EncryptedData priv,
                            @Nullable DeterministicKey parent) {
        this(childNumberPath, chainCode, pub, null, parent);
        this.encryptedPrivateKey = checkNotNull(priv);
        this.keyCrypter = checkNotNull(crypter);
    }

    /**
     * Return the fingerprint of this key's parent as an int value, or zero if this key is the
     * root node of the key hierarchy.  Raise an exception if the arguments are inconsistent.
     * This method exists to avoid code repetition in the constructors.
     */
    private int ascertainParentFingerprint(DeterministicKey parentKey, int parentFingerprint)
    throws IllegalArgumentException {
        if (parentFingerprint != 0) {
            if (parent != null)
                checkArgument(parent.getFingerprint() == parentFingerprint,
                              "parent fingerprint mismatch",
                              Integer.toHexString(parent.getFingerprint()), Integer.toHexString(parentFingerprint));
            return parentFingerprint;
        } else return 0;
    }

    /**
     * Constructs a key from its components, including its public key data and possibly-redundant
     * information about its parent key.  Invoked when deserializing, but otherwise not something that
     * you normally should use.
     */
    private DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            LazyECPoint publicAsPoint,
                            @Nullable DeterministicKey parent,
                            int depth,
                            int parentFingerprint) {
        super(null, compressPoint(checkNotNull(publicAsPoint)));
        checkArgument(chainCode.length == 32);
        this.parent = parent;
        this.childNumberPath = checkNotNull(childNumberPath);
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.depth = depth;
        this.parentFingerprint = ascertainParentFingerprint(parent, parentFingerprint);
    }

    /**
     * Constructs a key from its components, including its private key data and possibly-redundant
     * information about its parent key.  Invoked when deserializing, but otherwise not something that
     * you normally should use.
     */
    private DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            BigInteger priv,
                            @Nullable DeterministicKey parent,
                            int depth,
                            int parentFingerprint) {
        super(priv, compressPoint(ECKey.publicPointFromPrivate(priv)));
        checkArgument(chainCode.length == 32);
        this.parent = parent;
        this.childNumberPath = checkNotNull(childNumberPath);
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.depth = depth;
        this.parentFingerprint = ascertainParentFingerprint(parent, parentFingerprint);
    }

    
    /** Clones the key */
    public DeterministicKey(DeterministicKey keyToClone, DeterministicKey newParent) {
        super(keyToClone.priv, keyToClone.pub.get());
        this.parent = newParent;
        this.childNumberPath = keyToClone.childNumberPath;
        this.chainCode = keyToClone.chainCode;
        this.encryptedPrivateKey = keyToClone.encryptedPrivateKey;
        this.depth = this.childNumberPath.size();
        this.parentFingerprint = this.parent.getFingerprint();
    }

    /**
     * Returns the path through some {@link DeterministicHierarchy} which reaches this keys position in the tree.
     * A path can be written as 1/2/1 which means the first child of the root, the second child of that node, then
     * the first child of that node.
     */
    public ImmutableList<ChildNumber> getPath() {
        return childNumberPath;
    }

    /**
     * Returns the path of this key as a human readable string starting with M to indicate the master key.
     */
    public String getPathAsString() {
        return HDUtils.formatPath(getPath());
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
        return Utils.sha256hash160(getPubKey());
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
     * Returns the same key with the private bytes removed. May return the same instance. The purpose of this is to save
     * memory: the private key can always be very efficiently rederived from a parent that a private key, so storing
     * all the private keys in RAM is a poor tradeoff especially on constrained devices. This means that the returned
     * key may still be usable for signing and so on, so don't expect it to be a true pubkey-only object! If you want
     * that then you should follow this call with a call to {@link #dropParent()}.
     */
    public DeterministicKey dropPrivateBytes() {
        if (isPubKeyOnly())
            return this;
        else
            return new DeterministicKey(getPath(), getChainCode(), pub, null, parent);
    }

    /**
     * <p>Returns the same key with the parent pointer removed (it still knows its own path and the parent fingerprint).</p>
     *
     * <p>If this key doesn't have private key bytes stored/cached itself, but could rederive them from the parent, then
     * the new key returned by this method won't be able to do that. Thus, using dropPrivateBytes().dropParent() on a
     * regular DeterministicKey will yield a new DeterministicKey that cannot sign or do other things involving the
     * private key at all.</p>
     */
    public DeterministicKey dropParent() {
        DeterministicKey key = new DeterministicKey(getPath(), getChainCode(), pub, priv, null);
        key.parentFingerprint = parentFingerprint;
        return key;
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
    public DeterministicKey encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) throws KeyCrypterException {
        throw new UnsupportedOperationException("Must supply a new parent for encryption");
    }

    public DeterministicKey encrypt(KeyCrypter keyCrypter, KeyParameter aesKey, @Nullable DeterministicKey newParent) throws KeyCrypterException {
        // Same as the parent code, except we construct a DeterministicKey instead of an ECKey.
        checkNotNull(keyCrypter);
        if (newParent != null)
            checkArgument(newParent.isEncrypted());
        final byte[] privKeyBytes = getPrivKeyBytes();
        checkState(privKeyBytes != null, "Private key is not available");
        EncryptedData encryptedPrivateKey = keyCrypter.encrypt(privKeyBytes, aesKey);
        DeterministicKey key = new DeterministicKey(childNumberPath, chainCode, keyCrypter, pub, encryptedPrivateKey, newParent);
        if (newParent == null)
            key.setCreationTimeSeconds(getCreationTimeSeconds());
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

    /** {@inheritDoc} */
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
     * Returns this keys {@link org.bitcoinj.crypto.KeyCrypter} <b>or</b> the keycrypter of its parent key.
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
    public ECDSASignature sign(Sha256Hash input, @Nullable KeyParameter aesKey) throws KeyCrypterException {
        if (isEncrypted()) {
            // If the key is encrypted, ECKey.sign will decrypt it first before rerunning sign. Decryption walks the
            // key heirarchy to find the private key (see below), so, we can just run the inherited method.
            return super.sign(input, aesKey);
        } else {
            // If it's not encrypted, derive the private via the parents.
            final BigInteger privateKey = findOrDerivePrivateKey();
            if (privateKey == null) {
                // This key is a part of a public-key only heirarchy and cannot be used for signing
                throw new MissingPrivateKeyException();
            }
            return super.doSign(input, privateKey);
        }
    }

    @Override
    public DeterministicKey decrypt(KeyCrypter keyCrypter, KeyParameter aesKey) throws KeyCrypterException {
        checkNotNull(keyCrypter);
        // Check that the keyCrypter matches the one used to encrypt the keys, if set.
        if (this.keyCrypter != null && !this.keyCrypter.equals(keyCrypter))
            throw new KeyCrypterException("The keyCrypter being used to decrypt the key is different to the one that was used to encrypt it");
        BigInteger privKey = findOrDeriveEncryptedPrivateKey(keyCrypter, aesKey);
        DeterministicKey key = new DeterministicKey(childNumberPath, chainCode, privKey, parent);
        if (!Arrays.equals(key.getPubKey(), getPubKey()))
            throw new KeyCrypterException("Provided AES key is wrong");
        if (parent == null)
            key.setCreationTimeSeconds(getCreationTimeSeconds());
        return key;
    }

    @Override
    public DeterministicKey decrypt(KeyParameter aesKey) throws KeyCrypterException {
        return (DeterministicKey) super.decrypt(aesKey);
    }

    // For when a key is encrypted, either decrypt our encrypted private key bytes, or work up the tree asking parents
    // to decrypt and re-derive.
    private BigInteger findOrDeriveEncryptedPrivateKey(KeyCrypter keyCrypter, KeyParameter aesKey) {
        if (encryptedPrivateKey != null)
            return new BigInteger(1, keyCrypter.decrypt(encryptedPrivateKey, aesKey));
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
                cursor.pub, new BigInteger(1, parentalPrivateKeyBytes), cursor.parent);
        // Now we have to rederive the keys along the path back to ourselves. That path can be found by just truncating
        // our path with the length of the parents path.
        ImmutableList<ChildNumber> path = childNumberPath.subList(cursor.getPath().size(), childNumberPath.size());
        for (ChildNumber num : path) {
            downCursor = HDKeyDerivation.deriveChildKey(downCursor, num);
        }
        // downCursor is now the same key as us, but with private key bytes.
        // If it's not, it means we tried decrypting with an invalid password and earlier checks e.g. for padding didn't
        // catch it.
        if (!downCursor.pub.equals(pub))
            throw new KeyCrypterException("Could not decrypt bytes");
        return checkNotNull(downCursor.priv);
    }

    /**
     * Derives a child at the given index using hardened derivation.  Note: <code>index</code> is
     * not the "i" value.  If you want the softened derivation, then use instead
     * <code>HDKeyDerivation.deriveChildKey(this, new ChildNumber(child, false))</code>.
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
        checkState(key != null, "Private key bytes not available");
        return key;
    }

    public byte[] serializePublic(NetworkParameters params) {
        return serialize(params, true);
    }

    public byte[] serializePrivate(NetworkParameters params) {
        return serialize(params, false);
    }

    private byte[] serialize(NetworkParameters params, boolean pub) {
        ByteBuffer ser = ByteBuffer.allocate(78);
        ser.putInt(pub ? params.getBip32HeaderPub() : params.getBip32HeaderPriv());
        ser.put((byte) getDepth());
        ser.putInt(getParentFingerprint());
        ser.putInt(getChildNumber().i());
        ser.put(getChainCode());
        ser.put(pub ? getPubKey() : getPrivKeyBytes33());
        checkState(ser.position() == 78);
        return ser.array();
    }

    public String serializePubB58(NetworkParameters params) {
        return toBase58(serialize(params, true));
    }

    public String serializePrivB58(NetworkParameters params) {
        return toBase58(serialize(params, false));
    }

    static String toBase58(byte[] ser) {
        return Base58.encode(addChecksum(ser));
    }

    /** Deserialize a base-58-encoded HD Key with no parent */
    public static DeterministicKey deserializeB58(String base58, NetworkParameters params) {
        return deserializeB58(null, base58, params);
    }

    /**
      * Deserialize a base-58-encoded HD Key.
      *  @param parent The parent node in the given key's deterministic hierarchy.
      *  @throws IllegalArgumentException if the base58 encoded key could not be parsed.
      */
    public static DeterministicKey deserializeB58(@Nullable DeterministicKey parent, String base58, NetworkParameters params) {
        return deserialize(params, Base58.decodeChecked(base58), parent);
    }

    /**
      * Deserialize an HD Key with no parent
      */
    public static DeterministicKey deserialize(NetworkParameters params, byte[] serializedKey) {
        return deserialize(params, serializedKey, null);
    }

    /**
      * Deserialize an HD Key.
     * @param parent The parent node in the given key's deterministic hierarchy.
     */
    public static DeterministicKey deserialize(NetworkParameters params, byte[] serializedKey, @Nullable DeterministicKey parent) {
        ByteBuffer buffer = ByteBuffer.wrap(serializedKey);
        int header = buffer.getInt();
        if (header != params.getBip32HeaderPriv() && header != params.getBip32HeaderPub())
            throw new IllegalArgumentException("Unknown header bytes: " + toBase58(serializedKey).substring(0, 4));
        boolean pub = header == params.getBip32HeaderPub();
        int depth = buffer.get() & 0xFF; // convert signed byte to positive int since depth cannot be negative
        final int parentFingerprint = buffer.getInt();
        final int i = buffer.getInt();
        final ChildNumber childNumber = new ChildNumber(i);
        ImmutableList<ChildNumber> path;
        if (parent != null) {
            if (parentFingerprint == 0)
                throw new IllegalArgumentException("Parent was provided but this key doesn't have one");
            if (parent.getFingerprint() != parentFingerprint)
                throw new IllegalArgumentException("Parent fingerprints don't match");
            path = HDUtils.append(parent.getPath(), childNumber);
            if (path.size() != depth)
                throw new IllegalArgumentException("Depth does not match");
        } else {
            if (depth >= 1)
                // We have been given a key that is not a root key, yet we lack the object representing the parent.
                // This can happen when deserializing an account key for a watching wallet.  In this case, we assume that
                // the client wants to conceal the key's position in the hierarchy.  The path is truncated at the
                // parent's node.
                path = ImmutableList.of(childNumber);
            else path = ImmutableList.of();
        }
        byte[] chainCode = new byte[32];
        buffer.get(chainCode);
        byte[] data = new byte[33];
        buffer.get(data);
        checkArgument(!buffer.hasRemaining(), "Found unexpected data in key");
        if (pub) {
            return new DeterministicKey(path, chainCode, new LazyECPoint(ECKey.CURVE.getCurve(), data), parent, depth, parentFingerprint);
        } else {
            return new DeterministicKey(path, chainCode, new BigInteger(1, data), parent, depth, parentFingerprint);
        }
    }

    /**
     * The creation time of a deterministic key is equal to that of its parent, unless this key is the root of a tree
     * in which case the time is stored alongside the key as per normal, see {@link org.bitcoinj.core.ECKey#getCreationTimeSeconds()}.
     */
    @Override
    public long getCreationTimeSeconds() {
        if (parent != null)
            return parent.getCreationTimeSeconds();
        else
            return super.getCreationTimeSeconds();
    }

    /**
     * The creation time of a deterministic key is equal to that of its parent, unless this key is the root of a tree.
     * Thus, setting the creation time on a leaf is forbidden.
     */
    @Override
    public void setCreationTimeSeconds(long newCreationTimeSeconds) {
        if (parent != null)
            throw new IllegalStateException("Creation time can only be set on root keys.");
        else
            super.setCreationTimeSeconds(newCreationTimeSeconds);
    }

    /**
     * Verifies equality of all fields but NOT the parent pointer (thus the same key derived in two separate heirarchy
     * objects will equal each other.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        DeterministicKey other = (DeterministicKey) o;
        return super.equals(other)
                && Arrays.equals(this.chainCode, other.chainCode)
                && Objects.equal(this.childNumberPath, other.childNumberPath);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(super.hashCode(), Arrays.hashCode(chainCode), childNumberPath);
    }

    @Override
    public String toString() {
        final MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this).omitNullValues();
        helper.add("pub", Utils.HEX.encode(pub.getEncoded()));
        helper.add("chainCode", HEX.encode(chainCode));
        helper.add("path", getPathAsString());
        if (creationTimeSeconds > 0)
            helper.add("creationTimeSeconds", creationTimeSeconds);
        helper.add("isEncrypted", isEncrypted());
        helper.add("isPubKeyOnly", isPubKeyOnly());
        return helper.toString();
    }

    @Override
    public void formatKeyWithAddress(boolean includePrivateKeys, StringBuilder builder, NetworkParameters params) {
        final Address address = toAddress(params);
        builder.append("  addr:").append(address);
        builder.append("  hash160:").append(Utils.HEX.encode(getPubKeyHash()));
        builder.append("  (").append(getPathAsString()).append(")\n");
        if (includePrivateKeys) {
            builder.append("  ").append(toStringWithPrivate(params)).append("\n");
        }
    }
}
