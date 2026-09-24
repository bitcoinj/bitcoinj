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
package org.bitcoinj.base;

import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.base.internal.Secp256k1Constants;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.secp.Secp256k1;
import org.bitcoinj.secp.SecpPubKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import static org.bitcoinj.base.BitcoinNetwork.TESTNET;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * WIP test that demonstrates getting a Bitcoin address using {@link Address#fromKey(ECPublicKey, ScriptType, BitcoinNetwork)},
 * which will (once finished) allow constructing address without {@code bitcoinj-core} or <b>secp256k1-jdk</b> or <b>Bouncy Castle</b>.
 * For now, we are passing {@link BouncyCastleProvider}, but when finished there will be a built-in provider in {@code bitcoinj-base}.
 */
public class AddressFromKeyTest {
    private static final Logger log = LoggerFactory.getLogger(AddressFromKeyTest.class);
    static final String ADDRESS_STRING = "tb1q0yy3juscd3zfavw76g4h3eqdqzda7qyf7pcpwg";
    static final Address ADDRESS = AddressParser.getDefault().parseAddress(ADDRESS_STRING);
    static final byte[] PUBKEY =  ByteUtils.parseHex("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");

    public AddressFromKeyTest() {
        // Install [BouncyCastleProvider] for `RIPEMD160`.
        int preferencePosition = Security.addProvider(new BouncyCastleProvider());
        // `preferencePosition` will be -1 if already installed.
        log.info("Installed BouncyCastleProvider with preference position: {}", preferencePosition);
    }

    /**
     * Test with bitcoinj-core's ECKey implementation
     */
    @Test
    public void testAddressFromECKey() {
        ECKey key = ECKey.fromPrivate(
                ByteUtils.parseHex("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf"));

        Address address = Address.fromKey(key, ScriptType.P2WPKH, TESTNET);

        assertArrayEquals(PUBKEY, key.getEncoded());
        assertTrue(address instanceof SegwitAddress);
        assertEquals(0, ((SegwitAddress) address).getWitnessVersion());
        assertEquals(ADDRESS, address);
    }

    /**
     * Test with the secp256k1-jdk implementation of ECPublicKey
     */
    @Test
    public void testAddressFromSecpJdkKey() {
        try (Secp256k1 secp = Secp256k1.getById(Secp256k1.ProviderId.BOUNCY_CASTLE)) {
            SecpPubKey key = secp.ecPubKeyParse(PUBKEY).get();
            Address address = Address.fromKey(key, ScriptType.P2WPKH, TESTNET);

            assertTrue(address instanceof SegwitAddress);
            assertEquals(0, ((SegwitAddress) address).getWitnessVersion());
            assertEquals(ADDRESS, address);
        }
    }

    /**
     * Test with an arbitrary (Secp256k1) implementation of ECPublicKey
     */
    @Test
    public void testAddressFromGenericKey() {
        TestSecpPubKey key = new TestSecpPubKey(PUBKEY);

        Address address = Address.fromKey(key, ScriptType.P2WPKH, TESTNET);

        assertTrue(address instanceof SegwitAddress);
        assertEquals(0, ((SegwitAddress) address).getWitnessVersion());
        assertEquals(ADDRESS, address);
    }

    /**
     * A basic implementation of  ECPublicKey that conforms to Secp256k1Constants
     */
    public static class TestSecpPubKey implements ECPublicKey {
        private final byte[] encodedPubKey;

        public TestSecpPubKey(byte[] encodedPubKey) {
            this.encodedPubKey = encodedPubKey;
        }

        @Override
        public ECPoint getW() {
            return ECKey.fromPrivate(encodedPubKey).getW();
        }

        @Override
        public ECParameterSpec getParams() {
            return Secp256k1Constants.EC_PARAMS;
        }

        @Override
        public String getAlgorithm() {
            return Secp256k1Constants.ALGORITHM_NAME;
        }

        @Override
        public String getFormat() {
            return Secp256k1Constants.COMPRESSED_FORMAT_NAME;
        }

        @Override
        public byte[] getEncoded() {
            return encodedPubKey;
        }
    }
}
