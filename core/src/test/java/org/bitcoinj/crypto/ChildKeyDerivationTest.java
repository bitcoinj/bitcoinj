/**
 * Copyright 2013 Matija Mazi.
 * Copyright 2014 Andreas Schildbach
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

import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.junit.Test;
import org.spongycastle.crypto.params.KeyParameter;

import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.*;

/**
 * This test is adapted from Armory's BIP 32 tests.
 */
public class ChildKeyDerivationTest {
    private static final int HDW_CHAIN_EXTERNAL = 0;
    private static final int HDW_CHAIN_INTERNAL = 1;

    @Test
    public void testChildKeyDerivation() throws Exception {
        String ckdTestVectors[] = {
                // test case 1:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "04" +  "6a04ab98d9e4774ad806e302dddeb63b" +
                        "ea16b5cb5f223ee77478e861bb583eb3" +
                        "36b6fbcb60b5b3d4f1551ac45e5ffc49" +
                        "36466e7d98f6c7c0ec736539f74691a6",
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",

                // test case 2:
                "be05d9ded0a73f81b814c93792f753b35c575fe446760005d44e0be13ba8935a",
                "02" +  "b530da16bbff1428c33020e87fc9e699" +
                        "cc9c753a63b8678ce647b7457397acef",
                "7012bc411228495f25d666d55fdce3f10a93908b5f9b9b7baa6e7573603a7bda"
        };

        for(int i = 0; i < 1; i++) {
            byte[] priv  = HEX.decode(ckdTestVectors[3 * i]);
            byte[] pub   = HEX.decode(ckdTestVectors[3 * i + 1]);
            byte[] chain = HEX.decode(ckdTestVectors[3 * i + 2]); // chain code

            //////////////////////////////////////////////////////////////////////////
            // Start with an extended PRIVATE key
            DeterministicKey ekprv = HDKeyDerivation.createMasterPrivKeyFromBytes(priv, chain);

            // Create two accounts
            DeterministicKey ekprv_0 = HDKeyDerivation.deriveChildKey(ekprv, 0);
            DeterministicKey ekprv_1 = HDKeyDerivation.deriveChildKey(ekprv, 1);

            // Create internal and external chain on Account 0
            DeterministicKey ekprv_0_EX = HDKeyDerivation.deriveChildKey(ekprv_0, HDW_CHAIN_EXTERNAL);
            DeterministicKey ekprv_0_IN = HDKeyDerivation.deriveChildKey(ekprv_0, HDW_CHAIN_INTERNAL);

            // Create three addresses on external chain
            DeterministicKey ekprv_0_EX_0 = HDKeyDerivation.deriveChildKey(ekprv_0_EX, 0);
            DeterministicKey ekprv_0_EX_1 = HDKeyDerivation.deriveChildKey(ekprv_0_EX, 1);
            DeterministicKey ekprv_0_EX_2 = HDKeyDerivation.deriveChildKey(ekprv_0_EX, 2);

            // Create three addresses on internal chain
            DeterministicKey ekprv_0_IN_0 = HDKeyDerivation.deriveChildKey(ekprv_0_IN, 0);
            DeterministicKey ekprv_0_IN_1 = HDKeyDerivation.deriveChildKey(ekprv_0_IN, 1);
            DeterministicKey ekprv_0_IN_2 = HDKeyDerivation.deriveChildKey(ekprv_0_IN, 2);

            // Now add a few more addresses with very large indices
            DeterministicKey ekprv_1_IN = HDKeyDerivation.deriveChildKey(ekprv_1, HDW_CHAIN_INTERNAL);
            DeterministicKey ekprv_1_IN_4095 = HDKeyDerivation.deriveChildKey(ekprv_1_IN, 4095);
//            ExtendedHierarchicKey ekprv_1_IN_4bil = HDKeyDerivation.deriveChildKey(ekprv_1_IN, 4294967295L);

            //////////////////////////////////////////////////////////////////////////
            // Repeat the above with PUBLIC key
            DeterministicKey ekpub = HDKeyDerivation.createMasterPubKeyFromBytes(HDUtils.toCompressed(pub), chain);

            // Create two accounts
            DeterministicKey ekpub_0 = HDKeyDerivation.deriveChildKey(ekpub, 0);
            DeterministicKey ekpub_1 = HDKeyDerivation.deriveChildKey(ekpub, 1);

            // Create internal and external chain on Account 0
            DeterministicKey ekpub_0_EX = HDKeyDerivation.deriveChildKey(ekpub_0, HDW_CHAIN_EXTERNAL);
            DeterministicKey ekpub_0_IN = HDKeyDerivation.deriveChildKey(ekpub_0, HDW_CHAIN_INTERNAL);

            // Create three addresses on external chain
            DeterministicKey ekpub_0_EX_0 = HDKeyDerivation.deriveChildKey(ekpub_0_EX, 0);
            DeterministicKey ekpub_0_EX_1 = HDKeyDerivation.deriveChildKey(ekpub_0_EX, 1);
            DeterministicKey ekpub_0_EX_2 = HDKeyDerivation.deriveChildKey(ekpub_0_EX, 2);

            // Create three addresses on internal chain
            DeterministicKey ekpub_0_IN_0 = HDKeyDerivation.deriveChildKey(ekpub_0_IN, 0);
            DeterministicKey ekpub_0_IN_1 = HDKeyDerivation.deriveChildKey(ekpub_0_IN, 1);
            DeterministicKey ekpub_0_IN_2 = HDKeyDerivation.deriveChildKey(ekpub_0_IN, 2);

            // Now add a few more addresses with very large indices
            DeterministicKey ekpub_1_IN = HDKeyDerivation.deriveChildKey(ekpub_1, HDW_CHAIN_INTERNAL);
            DeterministicKey ekpub_1_IN_4095 = HDKeyDerivation.deriveChildKey(ekpub_1_IN, 4095);
//            ExtendedHierarchicKey ekpub_1_IN_4bil = HDKeyDerivation.deriveChildKey(ekpub_1_IN, 4294967295L);

            assertEquals(hexEncodePub(ekprv.getPubOnly()), hexEncodePub(ekpub));
            assertEquals(hexEncodePub(ekprv_0.getPubOnly()), hexEncodePub(ekpub_0));
            assertEquals(hexEncodePub(ekprv_1.getPubOnly()), hexEncodePub(ekpub_1));
            assertEquals(hexEncodePub(ekprv_0_IN.getPubOnly()), hexEncodePub(ekpub_0_IN));
            assertEquals(hexEncodePub(ekprv_0_IN_0.getPubOnly()), hexEncodePub(ekpub_0_IN_0));
            assertEquals(hexEncodePub(ekprv_0_IN_1.getPubOnly()), hexEncodePub(ekpub_0_IN_1));
            assertEquals(hexEncodePub(ekprv_0_IN_2.getPubOnly()), hexEncodePub(ekpub_0_IN_2));
            assertEquals(hexEncodePub(ekprv_0_EX_0.getPubOnly()), hexEncodePub(ekpub_0_EX_0));
            assertEquals(hexEncodePub(ekprv_0_EX_1.getPubOnly()), hexEncodePub(ekpub_0_EX_1));
            assertEquals(hexEncodePub(ekprv_0_EX_2.getPubOnly()), hexEncodePub(ekpub_0_EX_2));
            assertEquals(hexEncodePub(ekprv_1_IN.getPubOnly()), hexEncodePub(ekpub_1_IN));
            assertEquals(hexEncodePub(ekprv_1_IN_4095.getPubOnly()), hexEncodePub(ekpub_1_IN_4095));
            //assertEquals(hexEncodePub(ekprv_1_IN_4bil.getPubOnly()), hexEncodePub(ekpub_1_IN_4bil));
        }
    }

    @Test
    public void inverseEqualsNormal() throws Exception {
        DeterministicKey key1 = HDKeyDerivation.createMasterPrivateKey("Wired / Aug 13th 2014 / Snowden: I Left the NSA Clues, But They Couldn't Find Them".getBytes());
        HDKeyDerivation.RawKeyBytes key2 = HDKeyDerivation.deriveChildKeyBytesFromPublic(key1.getPubOnly(), ChildNumber.ZERO, HDKeyDerivation.PublicDeriveMode.NORMAL);
        HDKeyDerivation.RawKeyBytes key3 = HDKeyDerivation.deriveChildKeyBytesFromPublic(key1.getPubOnly(), ChildNumber.ZERO, HDKeyDerivation.PublicDeriveMode.WITH_INVERSION);
        assertArrayEquals(key2.keyBytes, key3.keyBytes);
        assertArrayEquals(key2.chainCode, key3.chainCode);
    }

    @Test
    public void encryptedDerivation() throws Exception {
        // Check that encrypting a parent key in the heirarchy and then deriving from it yields a DeterministicKey
        // with no private key component, and that the private key bytes are derived on demand.
        KeyCrypter scrypter = new KeyCrypterScrypt();
        KeyParameter aesKey = scrypter.deriveKey("we never went to the moon");

        DeterministicKey key1 = HDKeyDerivation.createMasterPrivateKey("it was all a hoax".getBytes());
        DeterministicKey encryptedKey1 = key1.encrypt(scrypter, aesKey, null);
        DeterministicKey decryptedKey1 = encryptedKey1.decrypt(aesKey);
        assertEquals(key1, decryptedKey1);

        DeterministicKey key2 = HDKeyDerivation.deriveChildKey(key1, ChildNumber.ZERO);
        DeterministicKey derivedKey2 = HDKeyDerivation.deriveChildKey(encryptedKey1, ChildNumber.ZERO);
        assertTrue(derivedKey2.isEncrypted());   // parent is encrypted.
        DeterministicKey decryptedKey2 = derivedKey2.decrypt(aesKey);
        assertFalse(decryptedKey2.isEncrypted());
        assertEquals(key2, decryptedKey2);

        Sha256Hash hash = Sha256Hash.create("the mainstream media won't cover it. why is that?".getBytes());
        try {
            derivedKey2.sign(hash);
            fail();
        } catch (ECKey.KeyIsEncryptedException e) {
            // Ignored.
        }
        ECKey.ECDSASignature signature = derivedKey2.sign(hash, aesKey);
        assertTrue(derivedKey2.verify(hash, signature));
    }

    @Test
    public void pubOnlyDerivation() throws Exception {
        DeterministicKey key1 = HDKeyDerivation.createMasterPrivateKey("satoshi lives!".getBytes());
        DeterministicKey key2 = HDKeyDerivation.deriveChildKey(key1, ChildNumber.ZERO_HARDENED);
        DeterministicKey key3 = HDKeyDerivation.deriveChildKey(key2, ChildNumber.ZERO);
        DeterministicKey pubkey3 = HDKeyDerivation.deriveChildKey(key2.getPubOnly(), ChildNumber.ZERO);
        assertEquals(key3.getPubKeyPoint(), pubkey3.getPubKeyPoint());
    }

    @Test
    public void serializeToTextAndBytes() {
        DeterministicKey key1 = HDKeyDerivation.createMasterPrivateKey("satoshi lives!".getBytes());
        DeterministicKey key2 = HDKeyDerivation.deriveChildKey(key1, ChildNumber.ZERO_HARDENED);

        // Creation time can't survive the xpub serialization format unfortunately.
        key1.setCreationTimeSeconds(0);
        key2.setCreationTimeSeconds(0);

        {
            final String pub58 = key1.serializePubB58();
            final String priv58 = key1.serializePrivB58();
            final byte[] pub = key1.serializePublic();
            final byte[] priv = key1.serializePrivate();
            assertEquals("xpub661MyMwAqRbcF7mq7Aejj5xZNzFfgi3ABamE9FedDHVmViSzSxYTgAQGcATDo2J821q7Y9EAagjg5EP3L7uBZk11PxZU3hikL59dexfLkz3", pub58);
            assertEquals("xprv9s21ZrQH143K2dhN197jMx1ppxRBHFKJpMqdLsF1ewxncv7quRED8N5nksxphju3W7naj1arF56L5PUEWfuSk8h73Sb2uh7bSwyXNrjzhAZ", priv58);
            assertArrayEquals(new byte[]{4, -120, -78, 30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 57, -68, 93, -104, -97, 31, -105, -18, 109, 112, 104, 45, -77, -77, 18, 85, -29, -120, 86, -113, 26, 48, -18, -79, -110, -6, -27, 87, 86, 24, 124, 99, 3, 96, -33, -14, 67, -19, -47, 16, 76, -49, -11, -30, -123, 7, 56, 101, 91, 74, 125, -127, 61, 42, -103, 90, -93, 66, -36, 2, -126, -107, 30, 24, -111}, pub);
            assertArrayEquals(new byte[]{4, -120, -83, -28, 0, 0, 0, 0, 0, 0, 0, 0, 0, 57, -68, 93, -104, -97, 31, -105, -18, 109, 112, 104, 45, -77, -77, 18, 85, -29, -120, 86, -113, 26, 48, -18, -79, -110, -6, -27, 87, 86, 24, 124, 99, 0, -96, -75, 47, 90, -49, 92, -74, 92, -128, -125, 23, 38, -10, 97, -66, -19, 50, -112, 30, -111, -57, -124, 118, -86, 126, -35, -4, -51, 19, 109, 67, 116}, priv);
            assertEquals(DeterministicKey.deserializeB58(null, priv58), key1);
            assertEquals(DeterministicKey.deserializeB58(null, pub58).getPubKeyPoint(), key1.getPubKeyPoint());
            assertEquals(DeterministicKey.deserialize(null, priv), key1);
            assertEquals(DeterministicKey.deserialize(null, pub).getPubKeyPoint(), key1.getPubKeyPoint());
        }
        {
            final String pub58 = key2.serializePubB58();
            final String priv58 = key2.serializePrivB58();
            final byte[] pub = key2.serializePublic();
            final byte[] priv = key2.serializePrivate();
            assertEquals(DeterministicKey.deserializeB58(key1, priv58), key2);
            assertEquals(DeterministicKey.deserializeB58(key1, pub58).getPubKeyPoint(), key2.getPubKeyPoint());
            assertEquals(DeterministicKey.deserialize(key1, priv), key2);
            assertEquals(DeterministicKey.deserialize(key1, pub).getPubKeyPoint(), key2.getPubKeyPoint());
        }
    }

    private static String hexEncodePub(DeterministicKey pubKey) {
        return HEX.encode(pubKey.getPubKey());
    }
}
