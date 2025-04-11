/*
 * Copyright by the original author or authors.
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

import org.bitcoinj.crypto.secp.Secp256k1Constants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * A wrapper around a SECP256K1 ECPoint that delays decoding of the point for as long as possible. This is useful
 * because point encode/decode in Bouncy Castle is quite slow especially on Dalvik, as it often involves
 * decompression/recompression.
 * <p>
 * Apart from the lazy field {@link #point}, instances of this class are immutable.
 */
public final class LazyECPoint implements ECPublicKey {
    private static final ECCurve curve = ECKey.CURVE.getCurve();

    // bits will be null if LazyECPoint is constructed from an (already decoded) point
    @Nullable
    private final byte[] bits;
    private final boolean compressed;

    // This field is lazy - once set it won't change again. However, it can be set after construction.
    @Nullable
    private ECPoint point;

    /**
     * Construct a LazyECPoint from a public key. Due to the delayed decoding of the point the validation of the
     * public key is delayed too, e.g. until a getter is called.
     *
     * @param bits  public key bytes
     */
    public LazyECPoint(byte[] bits) {
        this.bits = bits;
        this.compressed = ECKey.isPubKeyCompressed(bits);
    }

    /**
     * Construct a LazyECPoint from an already decoded point.
     *
     * @param point      the wrapped point
     * @param compressed true if the represented public key is compressed
     */
    public LazyECPoint(ECPoint point, boolean compressed) {
        this.point = Objects.requireNonNull(point).normalize();
        this.compressed = compressed;
        this.bits = null;
    }

    /**
     * Construct a LazyECPoint from a Java ECPoint.
     *
     * @param point      the wrapped point
     */
    LazyECPoint(java.security.spec.ECPoint point) {
        this(toBouncy(point), true);
    }

    private static org.bouncycastle.math.ec.ECPoint toBouncy(java.security.spec.ECPoint point) {
        return point == java.security.spec.ECPoint.POINT_INFINITY
                ? curve.getInfinity()
                : curve.createPoint(point.getAffineX(), point.getAffineY());
    }

    /**
     * Returns a compressed version of this elliptic curve point. Returns the same point if it's already compressed.
     * See the {@link ECKey} class docs for a discussion of point compression.
     */
    public LazyECPoint compress() {
        return compressed ? this : new LazyECPoint(get(), true);
    }

    /**
     * Returns a decompressed version of this elliptic curve point. Returns the same point if it's already compressed.
     * See the {@link ECKey} class docs for a discussion of point compression.
     */
    public LazyECPoint decompress() {
        return !compressed ? this : new LazyECPoint(get(), false);
    }

    public ECPoint get() {
        if (point == null)
            point = curve.decodePoint(bits);
        return point;
    }

    /**
     * @return string representing the algorithm used with this key
     */
    @Override
    public String getAlgorithm() {
        return "Secp256k1";
    }

    /**
     * @return string representing encoded format of this key
     */
    @Override
    public String getFormat() {
        return "SEC";
    }

    /**
     * Convert from internal Bouncy Castle {@link ECPoint} to return
     * a {@code java.security.spec.ECPoint}.
     * @return Java Cryptography ECPoint instance
     */
    @Override
    public java.security.spec.ECPoint getW() {
        ECPoint bcPoint = get();
        return bcPoint.isInfinity()
                ? java.security.spec.ECPoint.POINT_INFINITY
                : new java.security.spec.ECPoint(
                    bcPoint.normalize().getAffineXCoord().toBigInteger(),
                    bcPoint.normalize().getAffineYCoord().toBigInteger());
    }

    /**
     * @return Java Cryptography type with Elliptic Curve parameters
     */
    @Override
    public java.security.spec.ECParameterSpec getParams() {
        return Secp256k1Constants.EC_PARAMS;
    }

    public byte[] getEncoded() {
        if (bits != null)
            return Arrays.copyOf(bits, bits.length);
        else
            return get().getEncoded(compressed);
    }

    // package-private
    boolean isCompressedInternal() {
        return compressed;
    }

    // package-private
    byte[] getEncodedInternal(boolean compressed) {
        if (compressed == isCompressedInternal() && bits != null)
            return Arrays.copyOf(bits, bits.length);
        else
            return get().getEncoded(compressed);
    }

    // Delegated methods.
    // These are deprecated now as we are migrating away from using the Bouncy Castle API directly.

    @Deprecated
    public ECPoint getDetachedPoint() {
        return get().getDetachedPoint();
    }

    @Deprecated
    public boolean isInfinity() {
        return get().isInfinity();
    }

    @Deprecated
    public ECPoint timesPow2(int e) {
        return get().timesPow2(e);
    }

    @Deprecated
    public ECFieldElement getYCoord() {
        return get().getYCoord();
    }

    @Deprecated
    public ECFieldElement[] getZCoords() {
        return get().getZCoords();
    }

    @Deprecated
    public boolean isNormalized() {
        return get().isNormalized();
    }

    @Deprecated
    public boolean isCompressed() {
        return isCompressedInternal() ;
    }

    @Deprecated
    public ECPoint multiply(BigInteger k) {
        return get().multiply(k);
    }

    @Deprecated
    public ECPoint subtract(ECPoint b) {
        return get().subtract(b);
    }

    @Deprecated
    public boolean isValid() {
        return get().isValid();
    }

    @Deprecated
    public ECPoint scaleY(ECFieldElement scale) {
        return get().scaleY(scale);
    }

    @Deprecated
    public ECFieldElement getXCoord() {
        return get().getXCoord();
    }

    @Deprecated
    public ECPoint scaleX(ECFieldElement scale) {
        return get().scaleX(scale);
    }

    @Deprecated
    public boolean equals(ECPoint other) {
        return get().equals(other);
    }

    @Deprecated
    public ECPoint negate() {
        return get().negate();
    }

    @Deprecated
    public ECPoint threeTimes() {
        return get().threeTimes();
    }

    @Deprecated
    public ECFieldElement getZCoord(int index) {
        return get().getZCoord(index);
    }

    @Deprecated
    public byte[] getEncoded(boolean compressed) {
        if (compressed == isCompressedInternal() && bits != null)
            return Arrays.copyOf(bits, bits.length);
        else
            return get().getEncoded(compressed);
    }

    @Deprecated
    public ECPoint add(ECPoint b) {
        return get().add(b);
    }

    @Deprecated
    public ECPoint twicePlus(ECPoint b) {
        return get().twicePlus(b);
    }

    @Deprecated
    public ECCurve getCurve() {
        return get().getCurve();
    }

    @Deprecated
    public ECPoint normalize() {
        return get().normalize();
    }

    @Deprecated
    public ECFieldElement getY() {
        return this.normalize().getYCoord();
    }

    @Deprecated
    public ECPoint twice() {
        return get().twice();
    }

    @Deprecated
    public ECFieldElement getAffineYCoord() {
        return get().getAffineYCoord();
    }

    @Deprecated
    public ECFieldElement getAffineXCoord() {
        return get().getAffineXCoord();
    }

    @Deprecated
    public ECFieldElement getX() {
        return this.normalize().getXCoord();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return Arrays.equals(getCanonicalEncoding(), ((LazyECPoint)o).getCanonicalEncoding());
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(getCanonicalEncoding());
    }

    private byte[] getCanonicalEncoding() {
        return getEncodedInternal(true);
    }
}
