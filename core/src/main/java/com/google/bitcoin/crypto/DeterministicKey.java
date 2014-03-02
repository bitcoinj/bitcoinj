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
import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.encoders.Hex;

import javax.annotation.Nullable;
import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Collections;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

// TODO: Merge this with a redesigned ECKey class.

/**
 * A deterministic key is a node in a {@link DeterministicHierarchy}. As per
 * <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">the BIP 32 specification</a> it is a pair (key, chaincode). If you
 * know its path in the tree you can derive more keys from this.
 */
public class DeterministicKey implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Joiner PATH_JOINER = Joiner.on("/");

    private final DeterministicKey parent;
    private ECPoint publicAsPoint;
    private final BigInteger privateAsFieldElement;
    private final ImmutableList<ChildNumber> childNumberPath;

    /** 32 bytes */
    private final byte[] chainCode;

    DeterministicKey(ImmutableList<ChildNumber> childNumberPath, byte[] chainCode,
                     @Nullable ECPoint publicAsPoint, @Nullable BigInteger privateKeyFieldElt,
                     @Nullable DeterministicKey parent) {
        checkArgument(chainCode.length == 32);
        this.parent = parent;
        this.childNumberPath = childNumberPath;
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.publicAsPoint = publicAsPoint == null ? null : HDUtils.compressedCopy(publicAsPoint);
        this.privateAsFieldElement = privateKeyFieldElt;
    }

    /**
     * Returns the path through some {@link DeterministicHierarchy} which reaches this keys position in the tree.
     * A path can be written as 1/2/1 which means the first child of the root, the second child of that node, then
     * the first child of that node.
     */
    public ImmutableList<ChildNumber> getChildNumberPath() {
        return childNumberPath;
    }

    private int getDepth() {
        return childNumberPath.size();
    }

    /**
     * Returns the last element of the path returned by {@link DeterministicKey#getChildNumberPath()}
     */
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
     * Returns the path of this key as a human readable string starting with M to indicate the master key.
     */
    public String getPath() {
        return PATH_JOINER.join(Iterables.concat(Collections.singleton("M"), getChildNumberPath()));
    }

    /**
     * Returns RIPE-MD160(SHA256(pub key bytes)).
     */
    public byte[] getIdentifier() {
        return Utils.sha256hash160(getPubKeyBytes());
    }

    ECPoint getPubPoint() {
        if (publicAsPoint == null) {
            checkNotNull(privateAsFieldElement);
            publicAsPoint = ECKey.CURVE.getG().multiply(privateAsFieldElement);
        }
        return HDUtils.compressedCopy(publicAsPoint);
    }

    public byte[] getPubKeyBytes() {
        return getPubPoint().getEncoded();
    }


    /** Returns the first 32 bits of the result of {@link #getIdentifier()}. */
    public byte[] getFingerprint() {
        // TODO: why is this different than armory's fingerprint? BIP 32: "The first 32 bits of the identifier are called the fingerprint."
        return Arrays.copyOfRange(getIdentifier(), 0, 4);
    }

    @Nullable
    public BigInteger getPrivAsFieldElement() {
        return privateAsFieldElement;
    }

    @Nullable
    public DeterministicKey getParent() {
        return parent;
    }

    /**
     * Returns the private key bytes, if they were provided during construction.
     */
    @Nullable
    public byte[] getPrivKeyBytes() {
        return privateAsFieldElement == null ? null : privateAsFieldElement.toByteArray();
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
        if (!hasPrivate()) return this;
        final DeterministicKey parentPub = getParent() == null ? null : getParent().getPubOnly();
        return new DeterministicKey(getChildNumberPath(), getChainCode(), getPubPoint(), null, parentPub);
    }

    public boolean hasPrivate() {
        return privateAsFieldElement != null;
    }

    public ECKey toECKey() {
        return new ECKey(getPrivKeyBytes(), getPubKeyBytes());
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
        ser.putInt(getChildNumber().getI());
        ser.put(getChainCode());
        ser.put(pub ? getPubKeyBytes() : getPrivKeyBytes33());
        assert ser.position() == 78;

        return ser.array();
    }

    @Override
    public String toString() {
        return MessageFormat.format("ExtendedHierarchicKey[pub: {0}]", new String(Hex.encode(getPubKeyBytes())));
    }
}
