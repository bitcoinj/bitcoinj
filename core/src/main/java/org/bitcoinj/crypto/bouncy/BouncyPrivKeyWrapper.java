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
package org.bitcoinj.crypto.bouncy;

import org.bitcoinj.crypto.Secp256k1PrivKey;
import org.bouncycastle.math.ec.custom.sec.SecP256K1FieldElement;

import java.math.BigInteger;

/**
 * Experimental Secp256k1PrivKey wrapper for a Bouncy Castle Private Key stored
 * as a {@link BigInteger}.
 */
public class BouncyPrivKeyWrapper implements Secp256k1PrivKey {
    private final BigInteger privKey;

    public BouncyPrivKeyWrapper(BigInteger privKey) {
        this.privKey = privKey;
    }

    public BouncyPrivKeyWrapper(SecP256K1FieldElement privKey) {
        this.privKey = privKey.toBigInteger();
    }

    @Override
    public byte[] getEncoded() {
        SecP256K1FieldElement fe = new SecP256K1FieldElement(privKey);
        return fe.getEncoded();
    }

    @Override
    public BigInteger getS() {
        return privKey;
    }
}
