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


import com.google.bitcoin.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.io.ByteArrayInputStream;

import static org.junit.Assert.assertEquals;

public class BitcoinSerializerTest
{
    @Test
    public void testVersion() throws Exception {
        BitcoinSerializer bs = new BitcoinSerializer(NetworkParameters.prodNet(), false);
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
        BitcoinSerializer bs = new BitcoinSerializer(NetworkParameters.prodNet(), false);
        // the actual data from https://en.bitcoin.it/wiki/Protocol_specification#verack
        ByteArrayInputStream bais = new ByteArrayInputStream(Hex.decode("f9beb4d976657261636b00000000000000000000"));
        VersionAck va = (VersionAck)bs.deserialize(bais);

    }

    @Test
    public void testAddr() throws Exception {
        BitcoinSerializer bs = new BitcoinSerializer(NetworkParameters.prodNet(), true);
        // the actual data from https://en.bitcoin.it/wiki/Protocol_specification#addr
        ByteArrayInputStream bais = new ByteArrayInputStream(Hex.decode("f9beb4d96164647200000000000000001f000000" +
                "ed52399b01e215104d010000000000000000000000000000000000ffff0a000001208d"));
        AddressMessage a = (AddressMessage)bs.deserialize(bais);
        assertEquals(1, a.addresses.size());
        PeerAddress pa = a.addresses.get(0);
        assertEquals(8333, pa.port);
        assertEquals("10.0.0.1", pa.addr.getHostAddress());
    }
}
