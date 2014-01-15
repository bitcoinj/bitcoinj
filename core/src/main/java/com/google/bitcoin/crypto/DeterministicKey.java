/**
 * Copyright 2013 Matija Mazi.
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
package com.google.bitcoin.crypto;

import com.google.bitcoin.core.Base58;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.Utils;
import com.google.common.base.Objects;
import com.google.common.collect.ImmutableList;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.encoders.Hex;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

import static com.google.common.base.Preconditions.*;

/**
 * A deterministic key is a node in a {@link DeterministicHierarchy}. As per
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">the BIP 32 specification</a> it is a pair
 * (key, chaincode). If you know its path in the tree and its chain code you can derive more keys from this. To obtain
 * one of these, you can call {@link HDKeyDerivation#createMasterPrivateKey(byte[])}.
 */
public class DeterministicKey extends ECKey {
    private static final long serialVersionUID = 1L;

    private final DeterministicKey parent;
    private final ImmutableList<ChildNumber> childNumberPath;

    /** 32 bytes */
    private final byte[] chainCode;

    /** Constructs a key from its components. This is not normally something you should use. */
    public DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            ECPoint publicAsPoint,
                            @Nullable BigInteger priv,
                            @Nullable DeterministicKey parent) {
        super(priv, compressPoint(checkNotNull(publicAsPoint)));
        checkArgument(chainCode.length == 32);
        this.parent = parent;
        this.childNumberPath = checkNotNull(childNumberPath);
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
    }

    /** Constructs a key from its components. This is not normally something you should use. */
    public DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            BigInteger priv,
                            @Nullable DeterministicKey parent) {
        super(priv, compressPoint(ECKey.CURVE.getG().multiply(priv)));
        checkArgument(chainCode.length == 32);
        this.parent = parent;
        this.childNumberPath = checkNotNull(childNumberPath);
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
    }

    /** Constructs a key from its components. This is not normally something you should use. */
    public DeterministicKey(ImmutableList<ChildNumber> childNumberPath,
                            byte[] chainCode,
                            @Nullable DeterministicKey parent,
                            ECPoint pub,
                            EncryptedData priv,
                            KeyCrypter crypter) {
        this(childNumberPath, chainCode, pub, null, parent);
        this.encryptedPrivateKey = checkNotNull(priv);
        this.keyCrypter = checkNotNull(crypter);
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

    private int getDepth() {
        return childNumberPath.size();
    }

    /** Returns the last element of the path returned by {@link DeterministicKey#getPath()} */
    public ChildNumber getChildNumber() {
        return getDepth() == 0 ? ChildNumber.ZERO : childNumberPath.get(childNumberPath.size() - 1);
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
    public byte[] getFingerprint() {
        // TODO: why is this different than armory's fingerprint? BIP 32: "The first 32 bits of the identifier are called the fingerprint."
        return Arrays.copyOfRange(getIdentifier(), 0, 4);
    }

    @Nullable
    public DeterministicKey getParent() {
        return parent;
    }

    /**
     * @return private key bytes, padded with zeros to 33 bytes.
     */
    public byte[] getPrivKeyBytes33() {
        byte[] bytes33 = new byte[33];
        byte[] priv = checkNotNull(getPrivKeyBytes(), "Private key missing");
        System.arraycopy(priv, 0, bytes33, 33 - priv.length, priv.length);
        return bytes33;
    }

    /**
     * Returns the same key with the private part removed. May return the same instance.
     */
    public DeterministicKey getPubOnly() {
        if (isPubKeyOnly()) return this;
        final DeterministicKey parentPub = getParent() == null ? null : getParent().getPubOnly();
        return new DeterministicKey(getPath(), getChainCode(), getPubKeyPoint(), null, parentPub);
    }

    public String serializePubB58() {
        return toBase58(serialize(true));
    }

    public String serializePrivB58() {
        return toBase58(serialize(false));
    }

    static String toBase58(byte[] ser) {
        return Base58.encode(addChecksum(ser));
    }

    static byte[] addChecksum(byte[] input) {
        int inputLength = input.length;
        byte[] checksummed = new byte[inputLength + 4];
        System.arraycopy(input, 0, checksummed, 0, inputLength);
        byte[] checksum = Utils.doubleDigest(input);
        System.arraycopy(checksum, 0, checksummed, inputLength, 4);
        return checksummed;
    }

    /** {@inheritDoc} */
    @Override
    public DeterministicKey encrypt(KeyCrypter keyCrypter, KeyParameter aesKey) throws KeyCrypterException {
        // Same as the parent code, except we construct a DeterministicKey instead of an ECKey.
        checkNotNull(keyCrypter);
        final byte[] privKeyBytes = getPrivKeyBytes();
        checkState(privKeyBytes != null, "Private key is not available");
        EncryptedData encryptedPrivateKey = keyCrypter.encrypt(privKeyBytes, aesKey);
        return new DeterministicKey(childNumberPath, chainCode, parent, pub, encryptedPrivateKey, keyCrypter);
    }

    /**
     * A determinstic key is considered to be encrypted if it has access to encrypted private key bytes, OR if its
     * parent does. The reason is because the parent would be encrypted under the same key and this key knows how to
     * rederive its own private key bytes from the parent, if needed.
     */
    @Override
    public boolean isEncrypted() {
        return priv == null && (super.isEncrypted() || (parent != null && parent.isEncrypted()));
    }

    /**
     * Returns this keys {@link com.google.bitcoin.crypto.KeyCrypter} <b>or</b> the keycrypter of its parent key.
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
    public DeterministicKey decrypt(KeyCrypter keyCrypter, KeyParameter aesKey) throws KeyCrypterException {
        checkNotNull(keyCrypter);
        // Check that the keyCrypter matches the one used to encrypt the keys, if set.
        if (this.keyCrypter != null && !this.keyCrypter.equals(keyCrypter))
            throw new KeyCrypterException("The keyCrypter being used to decrypt the key is different to the one that was used to encrypt it");
        BigInteger privKey = findOrDerivePrivateKey(keyCrypter, aesKey);
        DeterministicKey key = new DeterministicKey(childNumberPath, chainCode, privKey, parent);
        if (!Arrays.equals(key.getPubKey(), getPubKey()))
            throw new KeyCrypterException("Provided AES key is wrong");
        return key;
    }

    // For when a key is encrypted, either decrypt our encrypted private key bytes, or work up the tree asking parents
    // to decrypt and re-derive.
    private BigInteger findOrDerivePrivateKey(KeyCrypter keyCrypter, KeyParameter aesKey) {
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
        DeterministicKey downCursor = new DeterministicKey(cursor.childNumberPath, cursor.chainCode,
                cursor.pub, new BigInteger(1, parentalPrivateKeyBytes), cursor.parent);
        // Now we have to rederive the keys along the path back to ourselves. That path can be found by just truncating
        // our path with the length of the parents path.
        ImmutableList<ChildNumber> path = childNumberPath.subList(cursor.getDepth(), childNumberPath.size());
        for (ChildNumber num : path) {
            downCursor = HDKeyDerivation.deriveChildKey(downCursor, num);
        }
        // downCursor is now the same key as us, but with private key bytes.
        checkState(downCursor.pub.equals(pub));
        return checkNotNull(downCursor.priv);
    }

    public byte[] serializePublic() {
        return serialize(true);
    }

    public byte[] serializePrivate() {
        return serialize(false);
    }

    private byte[] serialize(boolean pub) {
        ByteBuffer ser = ByteBuffer.allocate(78);
        ser.putInt(pub ? 0x0488B21E : 0x0488ADE4);
        ser.put((byte) getDepth());
        if (parent == null) {
            ser.putInt(0);
        } else {
            ser.put(parent.getFingerprint());
        }
        ser.putInt(getChildNumber().i());
        ser.put(getChainCode());
        ser.put(pub ? getPubKey() : getPrivKeyBytes33());
        checkState(ser.position() == 78);
        return ser.array();
    }

    /**
     * Verifies equality of all fields but NOT the parent pointer (thus the same key derived in two separate heirarchy
     * objects will equal each other.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        DeterministicKey key = (DeterministicKey) o;

        if (!Arrays.equals(chainCode, key.chainCode)) return false;
        if (!childNumberPath.equals(key.childNumberPath)) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (parent != null ? parent.hashCode() : 0);
        result = 31 * result + childNumberPath.hashCode();
        result = 31 * result + Arrays.hashCode(chainCode);
        return result;
    }

    @Override
    public String toString() {
        return Objects.toStringHelper(this)
                .add("pub", new String(Hex.encode(getPubKey())))
                .add("chaincode", new String(Hex.encode(getChainCode())))
                .add("path", getPathAsString())
                .toString();
    }
}
