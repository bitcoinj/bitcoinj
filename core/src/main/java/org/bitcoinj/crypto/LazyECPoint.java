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
import org.bouncycastle.math.ec.ECPoint;

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

    private final boolean compressed;
    private final ECPoint point;

    /**
     * Construct a LazyECPoint from a public key. Due to the delayed decoding of the point the validation of the
     * public key is delayed too, e.g. until a getter is called.
     *
     * @param bits  public key bytes
     */
    public LazyECPoint(byte[] bits) {
        this.point = curve.decodePoint(bits);
        this.compressed = ECKey.isPubKeyCompressed(bits);
    }

    /**
     * Construct a compressed LazyECPoint from an already decoded point.
     * <p>
     * Compressed format is preferred.
     * @param point      the wrapped point
     */
    public LazyECPoint(ECPoint point) {
        this.point = Objects.requireNonNull(point).normalize();
        this.compressed = true;
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
    }

    /**
     * Returns a compressed version of this elliptic curve point. Returns the same point if it's already compressed.
     * See the {@link ECKey} class docs for a discussion of point compression.
     */
    public LazyECPoint compress() {
        return compressed ? this : new LazyECPoint(get());
    }

    /**
     * Returns a decompressed version of this elliptic curve point. Returns the same point if it's already compressed.
     * See the {@link ECKey} class docs for a discussion of point compression.
     */
    public LazyECPoint decompress() {
        return !compressed ? this : new LazyECPoint(get(), false);
    }

    public ECPoint get() {
        return point;
    }

    public byte[] getEncoded() {
        return get().getEncoded(compressed);
    }

    // package-private
    boolean isCompressedInternal() {
        return compressed;
    }

    // package-private
    byte[] getEncodedInternal(boolean compressed) {
        return get().getEncoded(compressed);
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
