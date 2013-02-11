/**
 * Copyright 2011 Google Inc.
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

package com.google.bitcoin.core;

import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SignatureException;
import java.util.Arrays;

import static com.google.bitcoin.core.Utils.reverseBytes;
import static org.junit.Assert.*;

public class ECKeyTest {
    @Test
    public void testSignatures() {
        // Test that we can construct an ECKey from a private key (deriving the public from the private), then signing
        // a message with it.
        BigInteger privkey = new BigInteger(1, Hex.decode("180cb41c7c600be951b5d3d0a7334acc7506173875834f7a6c4c786a28fcbb19"));
        ECKey key = new ECKey(privkey);
        byte[] output = key.sign(Sha256Hash.ZERO_HASH).encodeToDER();
        assertTrue(key.verify(Sha256Hash.ZERO_HASH.getBytes(), output));

        // Test interop with a signature from elsewhere.
        byte[] sig = Hex.decode(
                "3046022100dffbc26774fc841bbe1c1362fd643609c6e42dcb274763476d87af2c0597e89e022100c59e3c13b96b316cae9fa0ab0260612c7a133a6fe2b3445b6bf80b3123bf274d");
        assertTrue(key.verify(Sha256Hash.ZERO_HASH.getBytes(), sig));
    }

    @Test
    public void testASN1Roundtrip() {
        byte[] privkeyASN1 = Hex.decode(
                "3082011302010104205c0b98e524ad188ddef35dc6abba13c34a351a05409e5d285403718b93336a4aa081a53081a2020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a144034200042af7a2aafe8dafd7dc7f9cfb58ce09bda7dce28653ab229b98d1d3d759660c672dd0db18c8c2d76aa470448e876fc2089ab1354c01a6e72cefc50915f4a963ee");
        ECKey decodedKey = ECKey.fromASN1(privkeyASN1);

        // Now re-encode and decode the ASN.1 to see if it is equivalent (it does not produce the exact same byte
        // sequence, some integers are padded now).
        ECKey roundtripKey = ECKey.fromASN1(decodedKey.toASN1());

        assertArrayEquals(decodedKey.getPrivKeyBytes(), roundtripKey.getPrivKeyBytes());

        for (ECKey key : new ECKey[] {decodedKey, roundtripKey}) {
            byte[] message = reverseBytes(Hex.decode(
                    "11da3761e86431e4a54c176789e41f1651b324d240d599a7067bee23d328ec2a"));
            byte[] output = key.sign(new Sha256Hash(message)).encodeToDER();
            assertTrue(key.verify(message, output));

            output = Hex.decode(
                    "304502206faa2ebc614bf4a0b31f0ce4ed9012eb193302ec2bcaccc7ae8bb40577f47549022100c73a1a1acc209f3f860bf9b9f5e13e9433db6f8b7bd527a088a0e0cd0a4c83e9");
            assertTrue(key.verify(message, output));
        }
        
        // Try to sign with one key and verify with the other.
        byte[] message = reverseBytes(Hex.decode(
            "11da3761e86431e4a54c176789e41f1651b324d240d599a7067bee23d328ec2a"));
        assertTrue(roundtripKey.verify(message, decodedKey.sign(new Sha256Hash(message)).encodeToDER()));
        assertTrue(decodedKey.verify(message, roundtripKey.sign(new Sha256Hash(message)).encodeToDER()));
    }

    @Test
    public void testKeyPairRoundtrip() {
        byte[] privkeyASN1 = Hex.decode(
                "3082011302010104205c0b98e524ad188ddef35dc6abba13c34a351a05409e5d285403718b93336a4aa081a53081a2020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a144034200042af7a2aafe8dafd7dc7f9cfb58ce09bda7dce28653ab229b98d1d3d759660c672dd0db18c8c2d76aa470448e876fc2089ab1354c01a6e72cefc50915f4a963ee");
        ECKey decodedKey = ECKey.fromASN1(privkeyASN1);

        // Now re-encode and decode the ASN.1 to see if it is equivalent (it does not produce the exact same byte
        // sequence, some integers are padded now).
        ECKey roundtripKey =
            new ECKey(decodedKey.getPrivKeyBytes(), decodedKey.getPubKey());

        for (ECKey key : new ECKey[] {decodedKey, roundtripKey}) {
            byte[] message = reverseBytes(Hex.decode(
                    "11da3761e86431e4a54c176789e41f1651b324d240d599a7067bee23d328ec2a"));
            byte[] output = key.sign(new Sha256Hash(message)).encodeToDER();
            assertTrue(key.verify(message, output));

            output = Hex.decode(
                    "304502206faa2ebc614bf4a0b31f0ce4ed9012eb193302ec2bcaccc7ae8bb40577f47549022100c73a1a1acc209f3f860bf9b9f5e13e9433db6f8b7bd527a088a0e0cd0a4c83e9");
            assertTrue(key.verify(message, output));
        }
        
        // Try to sign with one key and verify with the other.
        byte[] message = reverseBytes(Hex.decode(
            "11da3761e86431e4a54c176789e41f1651b324d240d599a7067bee23d328ec2a"));
        assertTrue(roundtripKey.verify(message, decodedKey.sign(new Sha256Hash(message)).encodeToDER()));
        assertTrue(decodedKey.verify(message, roundtripKey.sign(new Sha256Hash(message)).encodeToDER()));
    }

    @Test
    public void base58Encoding() throws Exception {
        String addr = "mqAJmaxMcG5pPHHc3H3NtyXzY7kGbJLuMF";
        String privkey = "92shANodC6Y4evT5kFzjNFQAdjqTtHAnDTLzqBBq4BbKUPyx6CD";
        ECKey key = new DumpedPrivateKey(NetworkParameters.testNet(), privkey).getKey();
        assertEquals(privkey, key.getPrivateKeyEncoded(NetworkParameters.testNet()).toString());
        assertEquals(addr, key.toAddress(NetworkParameters.testNet()).toString());
    }

    @Test
    public void base58Encoding_leadingZero() throws Exception {
        String privkey = "91axuYLa8xK796DnBXXsMbjuc8pDYxYgJyQMvFzrZ6UfXaGYuqL";
        ECKey key = new DumpedPrivateKey(NetworkParameters.testNet(), privkey).getKey();
        assertEquals(privkey, key.getPrivateKeyEncoded(NetworkParameters.testNet()).toString());
        assertEquals(0, key.getPrivKeyBytes()[0]);
    }

    @Test
    public void base58Encoding_stress() throws Exception {
        // Replace the loop bound with 1000 to get some keys with leading zero byte
        for (int i = 0 ; i < 20 ; i++) {
            ECKey key = new ECKey();
            ECKey key1 = new DumpedPrivateKey(NetworkParameters.testNet(),
                    key.getPrivateKeyEncoded(NetworkParameters.testNet()).toString()).getKey();
            assertEquals(Utils.bytesToHexString(key.getPrivKeyBytes()),
                    Utils.bytesToHexString(key1.getPrivKeyBytes()));
        }
    }

    @Test
    public void signTextMessage() throws Exception {
        ECKey key = new ECKey();
        String message = "Hello World!";
        String signatureBase64 = key.signMessage(message);
        System.out.println("Message signed with " + key.toAddress(NetworkParameters.prodNet()) + ": " + signatureBase64);
        // Should verify correctly.
        key.verifyMessage(message, signatureBase64);
        try {
            key.verifyMessage("Evil attacker says hello!", signatureBase64);
            fail();
        } catch (SignatureException e) {
            // OK.
        }
    }

    @Test
    public void verifyMessage() throws Exception {
        // Test vector generated by Bitcoin-Qt.
        String message = "hello";
        String sigBase64 = "HxNZdo6ggZ41hd3mM3gfJRqOQPZYcO8z8qdX2BwmpbF11CaOQV+QiZGGQxaYOncKoNW61oRuSMMF8udfK54XqI8=";
        Address expectedAddress = new Address(NetworkParameters.prodNet(), "14YPSNPi6NSXnUxtPAsyJSuw3pv7AU3Cag");
        ECKey key = ECKey.signedMessageToKey(message, sigBase64);
        Address gotAddress = key.toAddress(NetworkParameters.prodNet());
        assertEquals(expectedAddress, gotAddress);
    }

    @Test
    public void keyRecovery() throws Exception {
        ECKey key = new ECKey();
        String message = "Hello World!";
        Sha256Hash hash = Sha256Hash.create(message.getBytes());
        ECKey.ECDSASignature sig = key.sign(hash);
        key = new ECKey(null, key.getPubKey());
        boolean found = false;
        for (int i = 0; i < 4; i++) {
            ECKey key2 = ECKey.recoverFromSignature(i, sig, hash, true);
            if (key.equals(key2)) {
                found = true;
                break;
            }
        }
        assertTrue(found);
    }

    @Test
    public void roundTripDumpedPrivKey() throws Exception {
        ECKey key = new ECKey();
        assertTrue(key.isCompressed());
        NetworkParameters params = NetworkParameters.unitTests();
        String base58 = key.getPrivateKeyEncoded(params).toString();
        ECKey key2 = new DumpedPrivateKey(params, base58).getKey();
        assertTrue(key2.isCompressed());
        assertTrue(Arrays.equals(key.getPrivKeyBytes(), key2.getPrivKeyBytes()));
        assertTrue(Arrays.equals(key.getPubKey(), key2.getPubKey()));
    }
}
