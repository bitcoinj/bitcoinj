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

package org.bitcoinj.base.internal;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;

/**
 * This interface defines constants for SECP256K1 using standard Java Cryptography types.
 * It will eventually be replaces by similar definitions in <b>secp256k1-jdk</b>
 */
public interface Secp256k1Constants {
    String ALGORITHM_NAME = "Secp256k1";
    String COMPRESSED_FORMAT_NAME = "Compressed SEC";
    String UNCOMPRESSED_FORMAT_NAME = "Uncompressed SEC";

    /**
     * The prime {@code P}, that defines the secp256k1 field.
     * <p>
     * {@code P = 2²⁵⁶ − 2³² − 2⁹ − 2⁸ − 2⁷ − 2⁶ − 2⁴ − 1}
     * <p>
     */
    BigInteger P = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    /**
     * The prime {@code N}, that represents the order of the generator point, i.e. the number of points on the curve.
     */
    BigInteger N = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    ECFieldFp FIELD = new ECFieldFp(P);
    EllipticCurve CURVE = new EllipticCurve(FIELD, BigInteger.ZERO, BigInteger.valueOf(7));
    ECParameterSpec EC_PARAMS = new ECParameterSpec(CURVE,
            new java.security.spec.ECPoint(
                    new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),  // G.x
                    new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)), // G.y
            N,                                                                                                        // n
            1);                                                                                                       // h
}
