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

import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;

/**
 * This interface implements the Java Crypto {@link ECPublicKey} interface and identifies the key
 * as using the SECP256K1 curve.
 * <p>
 * Note: This class has been added to allow migration away from Bouncy Castle interfaces where possible
 * and to begin the migration process to the <a href="https://github.com/bitcoinj/secp256k1-jdk">bitcoinj/secp256k1-jdk</a>.
 * <p>
 * Once the migration to {@code bitcoinj/secp256k1-jdk} is finished, this interface will either extend or be replaced
 * by the {@code P256k1PubKey} class in {@code bitcoinj/secp256k1-jdk}.
 */
public interface Secp256k1PubKey extends ECPublicKey {
    // Java Crypto Types
    ECFieldFp FIELD = new ECFieldFp(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16));
    EllipticCurve CURVE = new EllipticCurve(FIELD, BigInteger.ZERO, BigInteger.valueOf(7));
    ECParameterSpec EC_PARAMS = new ECParameterSpec(CURVE,
            new java.security.spec.ECPoint(
                    new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),     // G.x
                    new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)),    // G.y
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16),         // n
            1);                                                                                                       // h

    @Override
    default String getAlgorithm() {
        return "Secp256k1";
    }

    @Override
    default String getFormat() {
        return "Uncompressed SEC";
    }

    /**
     * @return Return Parameters with a Java Crypto type
     */
    @Override
    default ECParameterSpec getParams() {
        return ECKey.EC_PARAMS;
    }
}
