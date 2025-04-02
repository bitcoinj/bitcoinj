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

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * A wrapper around a SECP256K1 ECPoint that delays decoding of the point for as long as possible. This is useful
 * because point encode/decode in Bouncy Castle is quite slow especially on Dalvik, as it often involves
 * decompression/recompression.
 * <p>
 * Apart from the lazy field {@link #point}, instances of this class are immutable.
 */
public final class LazyECPoint {
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

    public byte[] getEncoded() {
        if (bits != null)
            return Arrays.copyOf(bits, bits.length);
        else
            return get().getEncoded(compressed);
    }

    // Delegated methods.

    public ECPoint getDetachedPoint() {
        return get().getDetachedPoint();
    }

    public boolean isInfinity() {
        return get().isInfinity();
    }

    public ECPoint timesPow2(int e) {
        return get().timesPow2(e);
    }

    public ECFieldElement getYCoord() {
        return get().getYCoord();
    }

    public ECFieldElement[] getZCoords() {
        return get().getZCoords();
    }

    public boolean isNormalized() {
        return get().isNormalized();
    }

    public boolean isCompressed() {
        return compressed;
    }

    public ECPoint multiply(BigInteger k) {
        return get().multiply(k);
    }

    public ECPoint subtract(ECPoint b) {
        return get().subtract(b);
    }

    public boolean isValid() {
        return get().isValid();
    }

    public ECPoint scaleY(ECFieldElement scale) {
        return get().scaleY(scale);
    }

    public ECFieldElement getXCoord() {
        return get().getXCoord();
    }

    public ECPoint scaleX(ECFieldElement scale) {
        return get().scaleX(scale);
    }

    public boolean equals(ECPoint other) {
        return get().equals(other);
    }

    public ECPoint negate() {
        return get().negate();
    }

    public ECPoint threeTimes() {
        return get().threeTimes();
    }

    public ECFieldElement getZCoord(int index) {
        return get().getZCoord(index);
    }

    public byte[] getEncoded(boolean compressed) {
        if (compressed == isCompressed() && bits != null)
            return Arrays.copyOf(bits, bits.length);
        else
            return get().getEncoded(compressed);
    }

    public ECPoint add(ECPoint b) {
        return get().add(b);
    }

    public ECPoint twicePlus(ECPoint b) {
        return get().twicePlus(b);
    }

    public ECCurve getCurve() {
        return get().getCurve();
    }

    public ECPoint normalize() {
        return get().normalize();
    }

    public ECFieldElement getY() {
        return this.normalize().getYCoord();
    }

    public ECPoint twice() {
        return get().twice();
    }

    public ECFieldElement getAffineYCoord() {
        return get().getAffineYCoord();
    }

    public ECFieldElement getAffineXCoord() {
        return get().getAffineXCoord();
    }

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
        return getEncoded(true);
    }
}
