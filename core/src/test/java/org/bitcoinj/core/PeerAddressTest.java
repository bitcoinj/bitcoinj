/*
 * Copyright 2011 Google Inc.
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

import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.net.InetAddress;

import org.bitcoinj.params.MainNetParams;
import org.junit.Test;

public class PeerAddressTest {
    private static final NetworkParameters MAINNET = MainNetParams.get();
    
    @Test
    public void parse_ancientProtocolVersion() throws Exception {
        // copied from https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
        String hex = "010000000000000000000000000000000000ffff0a000001208d";
        PeerAddress pa = new PeerAddress(MAINNET, HEX.decode(hex), 0, 0);
        assertEquals(26, pa.length);
        assertEquals(VersionMessage.NODE_NETWORK, pa.getServices().longValue());
        assertEquals("10.0.0.1", pa.getAddr().getHostAddress());
        assertEquals(8333, pa.getPort());
    }

    @Test
    public void bitcoinSerialize_ancientProtocolVersion() throws Exception {
        PeerAddress pa = new PeerAddress(MAINNET, InetAddress.getByName(null), 8333, 0, BigInteger.ZERO);
        assertEquals(26, pa.length);        
        assertEquals("000000000000000000000000000000000000ffff7f000001208d", Utils.HEX.encode(pa.bitcoinSerialize()));
    }

    @Test
    public void roundtrip_ipv4_currentProtocolVersion() throws Exception {
        long time = Utils.currentTimeSeconds();
        PeerAddress pa = new PeerAddress(MAINNET, InetAddress.getByName("1.2.3.4"), 1234,
                NetworkParameters.ProtocolVersion.CURRENT.getBitcoinProtocolVersion(), BigInteger.ZERO);
        byte[] serialized = pa.bitcoinSerialize();
        PeerAddress pa2 = new PeerAddress(MAINNET, serialized, 0,
                NetworkParameters.ProtocolVersion.CURRENT.getBitcoinProtocolVersion());
        assertEquals("1.2.3.4", pa2.getAddr().getHostAddress());
        assertEquals(1234, pa2.getPort());
        assertEquals(BigInteger.ZERO, pa2.getServices());
        assertTrue(pa2.getTime() >= time && pa2.getTime() < time + 5); // potentially racy
    }

    @Test
    public void roundtrip_ipv4_ancientProtocolVersion() throws Exception {
        PeerAddress pa = new PeerAddress(MAINNET, InetAddress.getByName("1.2.3.4"), 1234, 0, BigInteger.ZERO);
        byte[] serialized = pa.bitcoinSerialize();
        PeerAddress pa2 = new PeerAddress(MAINNET, serialized, 0, 0);
        assertEquals("1.2.3.4", pa2.getAddr().getHostAddress());
        assertEquals(1234, pa2.getPort());
        assertEquals(BigInteger.ZERO, pa2.getServices());
        assertEquals(-1, pa2.getTime());
    }

    @Test
    public void roundtrip_ipv6_currentProtocolVersion() throws Exception {
        long time = Utils.currentTimeSeconds();
        PeerAddress pa = new PeerAddress(MAINNET, InetAddress.getByName("2001:db8:85a3:0:0:8a2e:370:7334"), 1234,
                NetworkParameters.ProtocolVersion.CURRENT.getBitcoinProtocolVersion(), BigInteger.ZERO);
        byte[] serialized = pa.bitcoinSerialize();
        PeerAddress pa2 = new PeerAddress(MAINNET, serialized, 0,
                NetworkParameters.ProtocolVersion.CURRENT.getBitcoinProtocolVersion());
        assertEquals("2001:db8:85a3:0:0:8a2e:370:7334", pa2.getAddr().getHostAddress());
        assertEquals(1234, pa2.getPort());
        assertEquals(BigInteger.ZERO, pa2.getServices());
        assertTrue(pa2.getTime() >= time && pa2.getTime() < time + 5); // potentially racy
    }

    @Test
    public void roundtrip_ipv6_ancientProtocolVersion() throws Exception {
        PeerAddress pa = new PeerAddress(MAINNET, InetAddress.getByName("2001:db8:85a3:0:0:8a2e:370:7334"), 1234, 0,
                BigInteger.ZERO);
        byte[] serialized = pa.bitcoinSerialize();
        PeerAddress pa2 = new PeerAddress(MAINNET, serialized, 0, 0);
        assertEquals("2001:db8:85a3:0:0:8a2e:370:7334", pa2.getAddr().getHostAddress());
        assertEquals(1234, pa2.getPort());
        assertEquals(BigInteger.ZERO, pa2.getServices());
        assertEquals(-1, pa2.getTime());
    }
}
