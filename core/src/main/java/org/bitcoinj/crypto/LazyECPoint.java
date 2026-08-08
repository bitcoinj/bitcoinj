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
import org.bouncycastle.math.ec.ECPoint;

import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Objects;

/**
 * A wrapper around a SECP256K1 ECPoint. The current implementation is no longer <q>lazy</q>.
 * <p>
 * Previous implementations of this class delayed decoding of the point for as long as possible. This was useful
 * because point encode/decode in Bouncy Castle was quite slow on Android/Dalvik implementations of that era.
 * On Modern hardware/sofware this is no longer necessary, so the class is now eager and fully immutable.
 */
public final class LazyECPoint implements ECPublicKey {
    private static final ECCurve curve = ECKey.CURVE.getCurve();

    private final boolean compressed;
    private final ECPoint point;

    /**
     * Construct a LazyECPoint from a public key.
     *
     * @param bits public key bytes
     */
    public LazyECPoint(byte[] bits) {
        this.point = curve.decodePoint(bits);
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
    }

    /**
     * Construct a LazyECPoint from a Java ECPoint.
     *
     * @param point the wrapped point
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
        return compressed ? this : new LazyECPoint(point, true);
    }

    /**
     * Returns a decompressed version of this elliptic curve point. Returns the same point if it's already compressed.
     * See the {@link ECKey} class docs for a discussion of point compression.
     */
    public LazyECPoint decompress() {
        return !compressed ? this : new LazyECPoint(point, false);
    }

    public ECPoint get() {
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
        return point.isInfinity()
                ? java.security.spec.ECPoint.POINT_INFINITY
                : new java.security.spec.ECPoint(
                    point.normalize().getAffineXCoord().toBigInteger(),
                    point.normalize().getAffineYCoord().toBigInteger());
    }

    /**
     * @return Java Cryptography type with Elliptic Curve parameters
     */
    @Override
    public java.security.spec.ECParameterSpec getParams() {
        return Secp256k1Constants.EC_PARAMS;
    }

    public byte[] getEncoded() {
        return point.getEncoded(compressed);
    }

    // package-private
    boolean isCompressedInternal() {
        return compressed;
    }

    // package-private
    byte[] getEncodedInternal(boolean compressed) {
        return point.getEncoded(compressed);
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
