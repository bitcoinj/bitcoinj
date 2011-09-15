/**
 * Copyright 2011 Noa Resare
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


import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.util.LinkedHashMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class BitcoinSerializerTest {
    private final byte[] addrMessage = Hex.decode("f9beb4d96164647200000000000000001f000000" +
            "ed52399b01e215104d010000000000000000000000000000000000ffff0a000001208d");

    private final byte[] txMessage = Hex.decode(
            "F9 BE B4 D9 74 78 00 00  00 00 00 00 00 00 00 00" +
            "02 01 00 00 E2 93 CD BE  01 00 00 00 01 6D BD DB" +
            "08 5B 1D 8A F7 51 84 F0  BC 01 FA D5 8D 12 66 E9" +
            "B6 3B 50 88 19 90 E4 B4  0D 6A EE 36 29 00 00 00" +
            "00 8B 48 30 45 02 21 00  F3 58 1E 19 72 AE 8A C7" +
            "C7 36 7A 7A 25 3B C1 13  52 23 AD B9 A4 68 BB 3A" +
            "59 23 3F 45 BC 57 83 80  02 20 59 AF 01 CA 17 D0" +
            "0E 41 83 7A 1D 58 E9 7A  A3 1B AE 58 4E DE C2 8D" +
            "35 BD 96 92 36 90 91 3B  AE 9A 01 41 04 9C 02 BF" +
            "C9 7E F2 36 CE 6D 8F E5  D9 40 13 C7 21 E9 15 98" +
            "2A CD 2B 12 B6 5D 9B 7D  59 E2 0A 84 20 05 F8 FC" +
            "4E 02 53 2E 87 3D 37 B9  6F 09 D6 D4 51 1A DA 8F" +
            "14 04 2F 46 61 4A 4C 70  C0 F1 4B EF F5 FF FF FF" +
            "FF 02 40 4B 4C 00 00 00  00 00 19 76 A9 14 1A A0" +
            "CD 1C BE A6 E7 45 8A 7A  BA D5 12 A9 D9 EA 1A FB" +
            "22 5E 88 AC 80 FA E9 C7  00 00 00 00 19 76 A9 14" +
            "0E AB 5B EA 43 6A 04 84  CF AB 12 48 5E FD A0 B7" +
            "8B 4E CC 52 88 AC 00 00  00 00");

    @Test
    public void testVersion() throws Exception {
        BitcoinSerializer bs = new BitcoinSerializer(NetworkParameters.prodNet(), false, null);
        // the actual data from https://en.bitcoin.it/wiki/Protocol_specification#version
        ByteArrayInputStream bais = new ByteArrayInputStream(Hex.decode("f9beb4d976657273696f6e0000000000550000009" +
                "c7c00000100000000000000e615104d00000000010000000000000000000000000000000000ffff0a000001daf6010000" +
                "000000000000000000000000000000ffff0a000002208ddd9d202c3ab457130055810100"));
        VersionMessage vm = (VersionMessage)bs.deserialize(bais);
        assertEquals(31900, vm.clientVersion);
        assertEquals(1292899814L, vm.time);
        assertEquals(98645L, vm.bestHeight);
    }


    @Test
    public void testVerack() throws Exception {
        BitcoinSerializer bs = new BitcoinSerializer(NetworkParameters.prodNet(), false, null);
        // the actual data from https://en.bitcoin.it/wiki/Protocol_specification#verack
        ByteArrayInputStream bais = new ByteArrayInputStream(Hex.decode("f9beb4d976657261636b00000000000000000000"));
        VersionAck va = (VersionAck)bs.deserialize(bais);

    }

    @Test
    public void testAddr() throws Exception {
        BitcoinSerializer bs = new BitcoinSerializer(NetworkParameters.prodNet(), true, null);
        // the actual data from https://en.bitcoin.it/wiki/Protocol_specification#addr
        ByteArrayInputStream bais = new ByteArrayInputStream(addrMessage);
        AddressMessage a = (AddressMessage)bs.deserialize(bais);
        assertEquals(1, a.addresses.size());
        PeerAddress pa = a.addresses.get(0);
        assertEquals(8333, pa.port);
        assertEquals("10.0.0.1", pa.addr.getHostAddress());
    }

    @Test
    public void testDeduplication() throws Exception {
        LinkedHashMap<Sha256Hash, Integer> dedupeList = BitcoinSerializer.createDedupeList();
        BitcoinSerializer bs = new BitcoinSerializer(NetworkParameters.prodNet(), true, dedupeList);
        ByteArrayInputStream bais = new ByteArrayInputStream(txMessage);
        Transaction tx = (Transaction)bs.deserialize(bais);
        assertNotNull(tx);
        bais.reset();
        tx = (Transaction)bs.deserialize(bais);
        assertNull(tx);
    }
}
