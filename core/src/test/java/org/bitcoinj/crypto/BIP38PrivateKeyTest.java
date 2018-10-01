/*
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

import org.bitcoinj.core.AddressFormatException;
import org.bitcoinj.core.Base58;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.crypto.BIP38PrivateKey.BadPassphraseException;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;

public class BIP38PrivateKeyTest {
    private static final NetworkParameters MAINNET = MainNetParams.get();
    private static final NetworkParameters TESTNET = TestNet3Params.get();

    @Test
    public void bip38testvector_noCompression_noEcMultiply_test1() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PYLQFfEh5hcTJNHHu6VaxfmsSE7H95UFbrDDWYDLmEiajmGxexdUWJHrb");
        ECKey key = encryptedKey.decrypt("TestingOneTwoThree");
        assertEquals("L1rZ5nfJRbANqCRy6Z8nWdFRuH2ZdjiK4JuFUn45SrTbjvcibNfC", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_noCompression_noEcMultiply_test2() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PYKaTxKyv3dSpJ8rirrA7qVvhqXsnmdHa61oDj81z4pzr84KivNwx9Q78");
        ECKey key = encryptedKey.decrypt("Satoshi");
        assertEquals("L3yxTHysc5W29ATgCTDnaYbM7JDs2B69x84grUpiaAzeZbsFeKn2", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_noCompression_noEcMultiply_test3() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PYPAkzcDE5pPBQfL71CVVQUZXWxvj25sxky7Zza19qXMcpkdcfTd5h1aG");
        StringBuilder passphrase = new StringBuilder();
        passphrase.appendCodePoint(0x03d2); // GREEK UPSILON WITH HOOK
        passphrase.appendCodePoint(0x01f4a9); // PILE OF POO
        ECKey key = encryptedKey.decrypt(passphrase.toString());
        assertEquals("Kxfvp5dqQRHkbPAEiNQ7QqyUN6maFkYGksQ8XEg221uFUMz42d7D", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_compression_noEcMultiply_test1() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PRT4Csfbup3aG5JQ3kUx8BcVaHWAgi4uNTS4ncFHF4C6kBk7NDSHL123f");
        ECKey key = encryptedKey.decrypt("TestingOneTwoThree");
        assertEquals("5JJkbtU3UrNp6VirD7roaeQMggngLEvsffckwqi6QzTwbKvetmS", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_compression_noEcMultiply_test2() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PRToFZF8cc6Fu7FeP768NBvx3MN7o3ForQ3mv5JpB8xQEVowELZxr1dKP");
        ECKey key = encryptedKey.decrypt("Satoshi");
        assertEquals("5J7r21cDmAWrgNyoC7k52jSSsiGTHzANkHKEBxpo3GTpM8HF5fC", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_ecMultiply_noCompression_noLotAndSequence_test1() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PRNtoGgcG6KkneK3Pnu4wDKnrbSiPakvEoG7tS8qeGUiaqimhEvtEmuYo");
        ECKey key = encryptedKey.decrypt("TestingOneTwoThree");
        assertEquals("5JkyYZ8MfKveTQcXTq5d6T8SuCuPEqqZ2wiNuqgeM8MoffzR2tz", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_ecMultiply_noCompression_noLotAndSequence_test2() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PRLNJXNagKxCytKrKPsp6yvkAnY6dbUdQi3yEMpdSPRUfUgbe8WgLF27D");
        ECKey key = encryptedKey.decrypt("Satoshi");
        assertEquals("5JGho7bh3KG6k3yDxeVY1B68Dy6PBAmfo2FGCibZw7bVAfPciUH", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_ecMultiply_noCompression_lotAndSequence_test1() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PRSjZABDvF6n8Ga9rFqKpKPKDa9guWMrk5WFmHbocEFd8cgGYaYfthBNP");
        ECKey key = encryptedKey.decrypt("MOLON LABE");
        assertEquals("5KBd2BvNBssUSE1Nx9b7uEx1fAb3rNKSwHeaN7QwapjTi4Uq9Wm", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bip38testvector_ecMultiply_noCompression_lotAndSequence_test2() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PRQjp8gj1V6VK7JVtpeaeNgBSvW7xn59S8EjwmGRUKYR3oK5tZj3tD8UU");
        ECKey key = encryptedKey.decrypt("ΜΟΛΩΝ ΛΑΒΕ");
        assertEquals("5JHZKRkPixsTEhWLqAQWAkCciv5c7VA47BYU7x8vEKCg4LhCX4v", key.getPrivateKeyEncoded(MAINNET)
                .toString());
    }

    @Test
    public void bitcoinpaperwallet_testnet() throws Exception {
        // values taken from bitcoinpaperwallet.com
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(TESTNET,
                "6PRPhQhmtw6dQu6jD8E1KS4VphwJxBS9Eh9C8FQELcrwN3vPvskv9NKvuL");
        ECKey key = encryptedKey.decrypt("password");
        assertEquals("93MLfjbY6ugAsLeQfFY6zodDa8izgm1XAwA9cpMbUTwLkDitopg", key.getPrivateKeyEncoded(TESTNET)
                .toString());
    }

    @Test
    public void bitaddress_testnet() throws Exception {
        // values taken from bitaddress.org
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(TESTNET,
                "6PfMmVHn153N3x83Yiy4Nf76dHUkXufe2Adr9Fw5bewrunGNeaw2QCpifb");
        ECKey key = encryptedKey.decrypt("password");
        assertEquals("91tCpdaGr4Khv7UAuUxa6aMqeN5GcPVJxzLtNsnZHTCndxkRcz2", key.getPrivateKeyEncoded(TESTNET)
                .toString());
    }

    @Test(expected = BadPassphraseException.class)
    public void badPassphrase() throws Exception {
        BIP38PrivateKey encryptedKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg");
        encryptedKey.decrypt("BAD");
    }

    @Test(expected = AddressFormatException.InvalidDataLength.class)
    public void fromBase58_invalidLength() {
        String base58 = Base58.encodeChecked(1, new byte[16]);
        BIP38PrivateKey.fromBase58(null, base58);
    }

    @Test
    public void testJavaSerialization() throws Exception {
        BIP38PrivateKey testKey = BIP38PrivateKey.fromBase58(TESTNET,
                "6PfMmVHn153N3x83Yiy4Nf76dHUkXufe2Adr9Fw5bewrunGNeaw2QCpifb");
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        new ObjectOutputStream(os).writeObject(testKey);
        BIP38PrivateKey testKeyCopy = (BIP38PrivateKey) new ObjectInputStream(
                new ByteArrayInputStream(os.toByteArray())).readObject();
        assertEquals(testKey, testKeyCopy);

        BIP38PrivateKey mainKey = BIP38PrivateKey.fromBase58(MAINNET,
                "6PfMmVHn153N3x83Yiy4Nf76dHUkXufe2Adr9Fw5bewrunGNeaw2QCpifb");
        os = new ByteArrayOutputStream();
        new ObjectOutputStream(os).writeObject(mainKey);
        BIP38PrivateKey mainKeyCopy = (BIP38PrivateKey) new ObjectInputStream(
                new ByteArrayInputStream(os.toByteArray())).readObject();
        assertEquals(mainKey, mainKeyCopy);
    }

    @Test
    public void cloning() throws Exception {
        BIP38PrivateKey a = BIP38PrivateKey.fromBase58(TESTNET, "6PfMmVHn153N3x83Yiy4Nf76dHUkXufe2Adr9Fw5bewrunGNeaw2QCpifb");
        // TODO: Consider overriding clone() in BIP38PrivateKey to narrow the type
        BIP38PrivateKey b = (BIP38PrivateKey) a.clone();

        assertEquals(a, b);
        assertNotSame(a, b);
    }

    @Test
    public void roundtripBase58() throws Exception {
        String base58 = "6PfMmVHn153N3x83Yiy4Nf76dHUkXufe2Adr9Fw5bewrunGNeaw2QCpifb";
        assertEquals(base58, BIP38PrivateKey.fromBase58(MAINNET, base58).toBase58());
    }
}
