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
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

/**
 * This interface implements the Java Crypto {@link ECPrivateKey} interface and identifies the key
 * as using the SECP256K1 curve.
 * <p>
 * Note: This class has been added to allow migration away from Bouncy Castle interfaces where possible
 * and to begin the migration process to the <a href="https://github.com/bitcoinj/secp256k1-jdk">bitcoinj/secp256k1-jdk</a>.
 * <p>
 * Once the migration to {@code bitcoinj/secp256k1-jdk} is finished, this interface will either extend or be replaced
 * by the {@code P256k1PrivKey} class in {@code bitcoinj/secp256k1-jdk}.
 */
public interface Secp256k1PrivKey extends ECPrivateKey {

    @Override
    default String getAlgorithm() {
        return "Secp256k1";
    }

    @Override
    default String getFormat() {
        return "Big-endian";
    }

    @Override
    default ECParameterSpec getParams() {
        return Secp256k1PubKey.EC_PARAMS;
    }

    /**
     * @return 32-bytes, Big endian with no prefix or suffix
     */
    @Override
    byte[] getEncoded();

    @Override
    BigInteger getS();
}
