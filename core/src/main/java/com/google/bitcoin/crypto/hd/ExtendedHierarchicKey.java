package com.google.bitcoin.crypto.hd;

import com.google.bitcoin.core.Base58;
import com.google.bitcoin.core.ECKey;
import com.google.bitcoin.core.Utils;
import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.util.encoders.Hex;

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Collections;

/**
 * @author Matija Mazi <br/>
 *
 * Extended key as per BIP 32 is a pair (key, chaincode).
 */
public class ExtendedHierarchicKey implements Serializable {
    public static final ChildNumber MASTER_CHILD_NUMBER = new ChildNumber(0);

    private static final long serialVersionUID = 1L;
    private static final Joiner PATH_JOINER = Joiner.on("/");

    private final ExtendedHierarchicKey parent;
    private ECPoint publicAsPoint;
    private final BigInteger privateAsFieldElement;
    private final ImmutableList<ChildNumber> childNumberPath;

    /** 32 bytes */
    private byte[] chainCode;

    ExtendedHierarchicKey(ImmutableList<ChildNumber> childNumberPath, byte[] chainCode, ECPoint publicAsPoint, BigInteger privateKeyFieldElt, ExtendedHierarchicKey parent) {
        assert chainCode.length == 32 : chainCode.length;
        this.parent = parent;
        this.childNumberPath = childNumberPath;
        this.chainCode = Arrays.copyOf(chainCode, chainCode.length);
        this.publicAsPoint = publicAsPoint == null ? null : HDUtils.compressedCopy(publicAsPoint);
        this.privateAsFieldElement = privateKeyFieldElt;
    }

    public ImmutableList<ChildNumber> getChildNumberPath() {
        return childNumberPath;
    }

    private int getDepth() {
        return childNumberPath.size();
    }

    public ChildNumber getChildNumber() {
        return getDepth() == 0 ? MASTER_CHILD_NUMBER : childNumberPath.get(childNumberPath.size() - 1);
    }

    byte[] getChainCode() {
        return chainCode;
    }

    public String getPath() {
        return PATH_JOINER.join(Iterables.concat(Collections.singleton("M"), getChildNumberPath()));
    }

    public byte[] getIdentifier() {
        return Utils.sha256hash160(getPubKeyBytes());
    }

    ECPoint getPubPoint() {
        if (publicAsPoint == null && privateAsFieldElement != null) {
            publicAsPoint = HDUtils.getEcParams().getG().multiply(privateAsFieldElement);
        }
        return HDUtils.compressedCopy(publicAsPoint);
    }

    public byte[] getPubKeyBytes() {
        return getPubPoint().getEncoded();
    }

    public byte[] getFingerprint() {
        // todo: why is this different than armory's fingerprint? BIP 32: "The first 32 bits of the identifier are called the fingerprint."
        return Arrays.copyOfRange(getIdentifier(), 0, 4);
    }

    public BigInteger getPrivAsFieldElement() {
        return privateAsFieldElement;
    }

    public ExtendedHierarchicKey getParent() {
        return parent;
    }

    public byte[] getPrivKeyBytes() {
        return privateAsFieldElement == null ? null : privateAsFieldElement.toByteArray();
    }

    /**
     * @return private key bytes, padded with zeros to 33 bytes.
     */
    public byte[] getPrivKeyBytes33() {
        byte[] bytes33 = new byte[33];
        byte[] priv = getPrivKeyBytes();
        System.arraycopy(priv, 0, bytes33, 33 - priv.length, priv.length);
        return bytes33;
    }

    /**
     * @return The same key with the private part removed. May return the same instance.
     */
    public ExtendedHierarchicKey getPubOnly() {
        return hasPrivate() ? new ExtendedHierarchicKey(getChildNumberPath(), getChainCode(), getPubPoint(), null, getParent() == null ? null : getParent().getPubOnly()) : this;
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
