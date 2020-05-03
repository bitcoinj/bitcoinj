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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;

import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.HDKeyDerivation.PublicDeriveMode;
import org.bouncycastle.crypto.params.KeyParameter;
import org.junit.Test;

import com.google.common.collect.ImmutableList;

/**
 * @author Andreas Schildbach
 */
public class HDKeyDerivationTest {
    private static final KeyCrypterScrypt KEY_CRYPTER = new KeyCrypterScrypt(2);
    private static final KeyParameter AES_KEY = KEY_CRYPTER.deriveKey("password");
    private static final ChildNumber CHILD_NUMBER = ChildNumber.ONE;
    private static final String EXPECTED_CHILD_CHAIN_CODE = "c4341fe988a2ae6240788c6b21df268b9286769915bed23c7649f263b3643ee8";
    private static final String EXPECTED_CHILD_PRIVATE_KEY = "48516d403070bc93f5e4d78c984cf2d71fc9799293b4eeb3de4f88e3892f523d";
    private static final String EXPECTED_CHILD_PUBLIC_KEY = "036d27f617ce7b0cbdce0abebd1c7aafc147bd406276e6a08d64d7a7ed0ca68f0e";

    @Test
    public void testDeriveFromPrivateParent() {
        DeterministicKey parent = new DeterministicKey(HDPath.M(), new byte[32], BigInteger.TEN,
                null);
        assertFalse(parent.isPubKeyOnly());
        assertFalse(parent.isEncrypted());

        DeterministicKey fromPrivate = HDKeyDerivation.deriveChildKeyFromPrivate(parent, CHILD_NUMBER);
        assertEquals(EXPECTED_CHILD_CHAIN_CODE, Utils.HEX.encode(fromPrivate.getChainCode()));
        assertEquals(EXPECTED_CHILD_PRIVATE_KEY, fromPrivate.getPrivateKeyAsHex());
        assertEquals(EXPECTED_CHILD_PUBLIC_KEY, fromPrivate.getPublicKeyAsHex());
        assertFalse(fromPrivate.isPubKeyOnly());
        assertFalse(fromPrivate.isEncrypted());

        DeterministicKey fromPublic = HDKeyDerivation.deriveChildKeyFromPublic(parent, CHILD_NUMBER,
                PublicDeriveMode.NORMAL);
        assertEquals(EXPECTED_CHILD_CHAIN_CODE, Utils.HEX.encode(fromPublic.getChainCode()));
        assertEquals(EXPECTED_CHILD_PRIVATE_KEY, fromPublic.getPrivateKeyAsHex());
        assertEquals(EXPECTED_CHILD_PUBLIC_KEY, fromPublic.getPublicKeyAsHex());
        assertFalse(fromPublic.isPubKeyOnly());
        assertFalse(fromPublic.isEncrypted());

        DeterministicKey fromPublicWithInversion = HDKeyDerivation.deriveChildKeyFromPublic(parent, CHILD_NUMBER,
                PublicDeriveMode.WITH_INVERSION);
        assertEquals(EXPECTED_CHILD_CHAIN_CODE, Utils.HEX.encode(fromPublicWithInversion.getChainCode()));
        assertEquals(EXPECTED_CHILD_PRIVATE_KEY, fromPublicWithInversion.getPrivateKeyAsHex());
        assertEquals(EXPECTED_CHILD_PUBLIC_KEY, fromPublicWithInversion.getPublicKeyAsHex());
        assertFalse(fromPublicWithInversion.isPubKeyOnly());
        assertFalse(fromPublicWithInversion.isEncrypted());
    }

    @Test
    public void testDeriveFromPublicParent() {
        DeterministicKey parent = new DeterministicKey(HDPath.M(), new byte[32], BigInteger.TEN,
                null).dropPrivateBytes();
        assertTrue(parent.isPubKeyOnly());
        assertFalse(parent.isEncrypted());

        try {
            HDKeyDerivation.deriveChildKeyFromPrivate(parent, CHILD_NUMBER);
            fail();
        } catch (IllegalArgumentException x) {
            // expected
        }

        DeterministicKey fromPublic = HDKeyDerivation.deriveChildKeyFromPublic(parent, CHILD_NUMBER,
                PublicDeriveMode.NORMAL);
        assertEquals(EXPECTED_CHILD_CHAIN_CODE, Utils.HEX.encode(fromPublic.getChainCode()));
        assertEquals(EXPECTED_CHILD_PUBLIC_KEY, fromPublic.getPublicKeyAsHex());
        assertTrue(fromPublic.isPubKeyOnly());
        assertFalse(fromPublic.isEncrypted());

        DeterministicKey fromPublicWithInversion = HDKeyDerivation.deriveChildKeyFromPublic(parent, CHILD_NUMBER,
                PublicDeriveMode.WITH_INVERSION);
        assertEquals(EXPECTED_CHILD_CHAIN_CODE, Utils.HEX.encode(fromPublicWithInversion.getChainCode()));
        assertEquals(EXPECTED_CHILD_PUBLIC_KEY, fromPublicWithInversion.getPublicKeyAsHex());
        assertTrue(fromPublicWithInversion.isPubKeyOnly());
        assertFalse(fromPublicWithInversion.isEncrypted());
    }

    @Test
    public void testDeriveFromEncryptedParent() {
        DeterministicKey parent = new DeterministicKey(HDPath.M(), new byte[32], BigInteger.TEN,
                null);
        parent = parent.encrypt(KEY_CRYPTER, AES_KEY, null);
        assertTrue(parent.isEncrypted());
        assertTrue(parent.isPubKeyOnly());

        try {
            HDKeyDerivation.deriveChildKeyFromPrivate(parent, CHILD_NUMBER);
            fail();
        } catch (IllegalArgumentException x) {
            // expected
        }

        DeterministicKey fromPublic = HDKeyDerivation.deriveChildKeyFromPublic(parent, CHILD_NUMBER,
                PublicDeriveMode.NORMAL);
        assertEquals(EXPECTED_CHILD_CHAIN_CODE, Utils.HEX.encode(fromPublic.getChainCode()));
        assertEquals(EXPECTED_CHILD_PUBLIC_KEY, fromPublic.getPublicKeyAsHex());
        assertTrue(fromPublic.isPubKeyOnly());
        assertTrue(fromPublic.isEncrypted());
        fromPublic = fromPublic.decrypt(AES_KEY);
        assertEquals(EXPECTED_CHILD_CHAIN_CODE, Utils.HEX.encode(fromPublic.getChainCode()));
        assertEquals(EXPECTED_CHILD_PRIVATE_KEY, fromPublic.getPrivateKeyAsHex());
        assertEquals(EXPECTED_CHILD_PUBLIC_KEY, fromPublic.getPublicKeyAsHex());

        DeterministicKey fromPublicWithInversion = HDKeyDerivation.deriveChildKeyFromPublic(parent, CHILD_NUMBER,
                PublicDeriveMode.WITH_INVERSION);
        assertEquals(EXPECTED_CHILD_CHAIN_CODE, Utils.HEX.encode(fromPublicWithInversion.getChainCode()));
        assertEquals(EXPECTED_CHILD_PUBLIC_KEY, fromPublicWithInversion.getPublicKeyAsHex());
        assertTrue(fromPublicWithInversion.isPubKeyOnly());
        assertTrue(fromPublicWithInversion.isEncrypted());
        fromPublicWithInversion = fromPublicWithInversion.decrypt(AES_KEY);
        assertEquals(EXPECTED_CHILD_CHAIN_CODE, Utils.HEX.encode(fromPublicWithInversion.getChainCode()));
        assertEquals(EXPECTED_CHILD_PRIVATE_KEY, fromPublicWithInversion.getPrivateKeyAsHex());
        assertEquals(EXPECTED_CHILD_PUBLIC_KEY, fromPublicWithInversion.getPublicKeyAsHex());
    }
}
