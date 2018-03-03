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

package org.bitcoinj.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;

import org.junit.Test;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;

public class DumpedPrivateKeyTest {
    private static final NetworkParameters MAINNET = MainNetParams.get();
    private static final NetworkParameters TESTNET = TestNet3Params.get();

    @Test
    public void checkNetwork() throws Exception {
        DumpedPrivateKey.fromBase58(MAINNET, "5HtUCLMFWNueqN9unpgX2DzjMg6SDNZyKRb8s3LJgpFg5ubuMrk");
    }

    @Test(expected = AddressFormatException.WrongNetwork.class)
    public void checkNetworkWrong() throws Exception {
        DumpedPrivateKey.fromBase58(TESTNET, "5HtUCLMFWNueqN9unpgX2DzjMg6SDNZyKRb8s3LJgpFg5ubuMrk");
    }

    @Test
    public void testJavaSerialization() throws Exception {

        DumpedPrivateKey key = new DumpedPrivateKey(MAINNET, new ECKey().getPrivKeyBytes(), true);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        new ObjectOutputStream(os).writeObject(key);
        DumpedPrivateKey keyCopy = (DumpedPrivateKey) new ObjectInputStream(new ByteArrayInputStream(os.toByteArray()))
                .readObject();
        assertEquals(key, keyCopy);
    }

    @Test
    public void cloning() throws Exception {
        DumpedPrivateKey a = new DumpedPrivateKey(MAINNET, new ECKey().getPrivKeyBytes(), true);
        // TODO: Consider overriding clone() in DumpedPrivateKey to narrow the type
        DumpedPrivateKey b = (DumpedPrivateKey) a.clone();

        assertEquals(a, b);
        assertNotSame(a, b);
    }

    @Test
    public void roundtripBase58() throws Exception {
        String base58 = "5HtUCLMFWNueqN9unpgX2DzjMg6SDNZyKRb8s3LJgpFg5ubuMrk"; // 32-bytes key
        DumpedPrivateKey dumpedPrivateKey = DumpedPrivateKey.fromBase58(null, base58);
        assertFalse(dumpedPrivateKey.isPubKeyCompressed());
        assertEquals(base58, dumpedPrivateKey.toBase58());
    }

    @Test
    public void roundtripBase58_compressed() throws Exception {
        String base58 = "cSthBXr8YQAexpKeh22LB9PdextVE1UJeahmyns5LzcmMDSy59L4"; // 33-bytes, compressed == true
        DumpedPrivateKey dumpedPrivateKey = DumpedPrivateKey.fromBase58(null, base58);
        assertTrue(dumpedPrivateKey.isPubKeyCompressed());
        assertEquals(base58, dumpedPrivateKey.toBase58());
    }

    @Test(expected = AddressFormatException.class)
    public void roundtripBase58_invalidCompressed() {
        String base58 = "5Kg5shEQWrf1TojaHTdc2kLuz5Mfh4uvp3cYu8uJHaHgfTGUbTD"; // 32-bytes key
        byte[] bytes = Base58.decodeChecked(base58);
        bytes = Arrays.copyOf(bytes, bytes.length + 1); // append a "compress" byte
        bytes[bytes.length - 1] = 0; // set it to false
        base58 = Base58.encode(bytes); // 33-bytes key, compressed == false
        DumpedPrivateKey.fromBase58(null, base58); // fail
    }

    @Test(expected = AddressFormatException.InvalidDataLength.class)
    public void fromBase58_tooShort() {
        String base58 = Base58.encodeChecked(MAINNET.dumpedPrivateKeyHeader, new byte[31]);
        DumpedPrivateKey.fromBase58(null, base58);
    }

    @Test(expected = AddressFormatException.InvalidDataLength.class)
    public void fromBase58_tooLong() {
        String base58 = Base58.encodeChecked(MAINNET.dumpedPrivateKeyHeader, new byte[34]);
        DumpedPrivateKey.fromBase58(null, base58);
    }

    @Test
    public void roundtripBase58_getKey() throws Exception {
        ECKey k = new ECKey().decompress();
        assertFalse(k.isCompressed());
        assertEquals(k.getPrivKey(),
                DumpedPrivateKey.fromBase58(null, k.getPrivateKeyAsWiF(MAINNET)).getKey().getPrivKey());
    }

    @Test
    public void roundtripBase58_compressed_getKey() throws Exception {
        ECKey k = new ECKey();
        assertTrue(k.isCompressed());
        assertEquals(k.getPrivKey(),
                DumpedPrivateKey.fromBase58(null, k.getPrivateKeyAsWiF(MAINNET)).getKey().getPrivKey());
    }
}
