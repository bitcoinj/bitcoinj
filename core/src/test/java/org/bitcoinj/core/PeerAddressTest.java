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

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import nl.jqno.equalsverifier.EqualsVerifier;
import nl.jqno.equalsverifier.Warning;
import org.bitcoinj.base.utils.ByteUtils;
import org.bitcoinj.params.MainNetParams;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.math.BigInteger;
import java.net.InetAddress;

import static org.bitcoinj.base.utils.ByteUtils.HEX;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(JUnitParamsRunner.class)
public class PeerAddressTest {
    private static final NetworkParameters MAINNET = MainNetParams.get();

    @Test
    public void equalsContract() {
        EqualsVerifier.forClass(PeerAddress.class)
                .suppress(Warning.NONFINAL_FIELDS)
                .withIgnoredFields("time", "parent", "params", "offset", "cursor", "length", "payload", "recached", "serializer")
                .usingGetClass()
                .verify();
    }

    @Test
    public void parse_versionVariant() {
        MessageSerializer serializer = MAINNET.getDefaultSerializer().withProtocolVersion(0);
        // copied from https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
        String hex = "010000000000000000000000000000000000ffff0a000001208d";
        PeerAddress pa = new PeerAddress(MAINNET, HEX.decode(hex), 0, null,
                serializer);
        assertEquals(26, pa.length);
        assertEquals(VersionMessage.NODE_NETWORK, pa.getServices().longValue());
        assertEquals("10.0.0.1", pa.getAddr().getHostAddress());
        assertEquals(8333, pa.getPort());
    }

    @Test
    public void bitcoinSerialize_versionVariant() throws Exception {
        MessageSerializer serializer = MAINNET.getDefaultSerializer().withProtocolVersion(0);
        PeerAddress pa = new PeerAddress(MAINNET, InetAddress.getByName(null), 8333, BigInteger.ZERO,
                serializer);
        assertEquals("000000000000000000000000000000000000ffff7f000001208d", ByteUtils.HEX.encode(pa.bitcoinSerialize()));
        assertEquals(26, pa.length);
    }

    @Test
    public void roundtrip_ipv4_addressV2Variant() throws Exception {
        long time = Utils.currentTimeSeconds();
        MessageSerializer serializer = MAINNET.getDefaultSerializer().withProtocolVersion(2);
        PeerAddress pa = new PeerAddress(MAINNET, InetAddress.getByName("1.2.3.4"), 1234, BigInteger.ZERO,
                serializer);
        byte[] serialized = pa.bitcoinSerialize();
        PeerAddress pa2 = new PeerAddress(MAINNET, serialized, 0, null, serializer);
        assertEquals("1.2.3.4", pa2.getAddr().getHostAddress());
        assertEquals(1234, pa2.getPort());
        assertEquals(BigInteger.ZERO, pa2.getServices());
        assertTrue(pa2.getTime() >= time && pa2.getTime() < time + 5); // potentially racy
    }

    @Test
    public void roundtrip_ipv4_addressVariant() throws Exception {
        long time = Utils.currentTimeSeconds();
        MessageSerializer serializer = MAINNET.getDefaultSerializer().withProtocolVersion(1);
        PeerAddress pa = new PeerAddress(MAINNET, InetAddress.getByName("1.2.3.4"), 1234, BigInteger.ZERO,
                serializer);
        byte[] serialized = pa.bitcoinSerialize();
        PeerAddress pa2 = new PeerAddress(MAINNET, serialized, 0, null, serializer);
        assertEquals("1.2.3.4", pa2.getAddr().getHostAddress());
        assertEquals(1234, pa2.getPort());
        assertEquals(BigInteger.ZERO, pa2.getServices());
        assertTrue(pa2.getTime() >= time && pa2.getTime() < time + 5); // potentially racy
    }

    @Test
    public void roundtrip_ipv4_versionVariant() throws Exception {
        MessageSerializer serializer = MAINNET.getDefaultSerializer().withProtocolVersion(0);
        PeerAddress pa = new PeerAddress(MAINNET, InetAddress.getByName("1.2.3.4"), 1234, BigInteger.ZERO,
                serializer);
        byte[] serialized = pa.bitcoinSerialize();
        PeerAddress pa2 = new PeerAddress(MAINNET, serialized, 0, null, serializer);
        assertEquals("1.2.3.4", pa2.getAddr().getHostAddress());
        assertEquals(1234, pa2.getPort());
        assertEquals(BigInteger.ZERO, pa2.getServices());
        assertEquals(-1, pa2.getTime());
    }

    @Test
    public void roundtrip_ipv6_addressV2Variant() throws Exception {
        long time = Utils.currentTimeSeconds();
        MessageSerializer serializer = MAINNET.getDefaultSerializer().withProtocolVersion(2);
        PeerAddress pa = new PeerAddress(MAINNET, InetAddress.getByName("2001:db8:85a3:0:0:8a2e:370:7334"), 1234,
                BigInteger.ZERO, serializer);
        byte[] serialized = pa.bitcoinSerialize();
        PeerAddress pa2 = new PeerAddress(MAINNET, serialized, 0, null, serializer);
        assertEquals("2001:db8:85a3:0:0:8a2e:370:7334", pa2.getAddr().getHostAddress());
        assertEquals(1234, pa2.getPort());
        assertEquals(BigInteger.ZERO, pa2.getServices());
        assertTrue(pa2.getTime() >= time && pa2.getTime() < time + 5); // potentially racy
    }

    @Test
    public void roundtrip_ipv6_addressVariant() throws Exception {
        long time = Utils.currentTimeSeconds();
        MessageSerializer serializer = MAINNET.getDefaultSerializer().withProtocolVersion(1);
        PeerAddress pa = new PeerAddress(MAINNET, InetAddress.getByName("2001:db8:85a3:0:0:8a2e:370:7334"), 1234,
                BigInteger.ZERO, serializer);
        byte[] serialized = pa.bitcoinSerialize();
        PeerAddress pa2 = new PeerAddress(MAINNET, serialized, 0, null, serializer);
        assertEquals("2001:db8:85a3:0:0:8a2e:370:7334", pa2.getAddr().getHostAddress());
        assertEquals(1234, pa2.getPort());
        assertEquals(BigInteger.ZERO, pa2.getServices());
        assertTrue(pa2.getTime() >= time && pa2.getTime() < time + 5); // potentially racy
    }

    @Test
    public void roundtrip_ipv6_versionVariant() throws Exception {
        MessageSerializer serializer = MAINNET.getDefaultSerializer().withProtocolVersion(0);
        PeerAddress pa = new PeerAddress(MAINNET, InetAddress.getByName("2001:db8:85a3:0:0:8a2e:370:7334"), 1234,
                BigInteger.ZERO, serializer);
        byte[] serialized = pa.bitcoinSerialize();
        PeerAddress pa2 = new PeerAddress(MAINNET, serialized, 0, null,
                serializer);
        assertEquals("2001:db8:85a3:0:0:8a2e:370:7334", pa2.getAddr().getHostAddress());
        assertEquals(1234, pa2.getPort());
        assertEquals(BigInteger.ZERO, pa2.getServices());
        assertEquals(-1, pa2.getTime());
    }

    @Test
    @Parameters(method = "deserializeToStringValues")
    public void deserializeToString(int version, String expectedToString, String hex) {
        MessageSerializer serializer = MAINNET.getDefaultSerializer().withProtocolVersion(version);
        PeerAddress pa = new PeerAddress(MAINNET, HEX.decode(hex), 0, null, serializer);

        assertEquals(expectedToString, pa.toString());
    }

    private Object[] deserializeToStringValues() {
        return new Object[]{
                new Object[]{0, "[10.0.0.1]:8333", "010000000000000000000000000000000000ffff0a000001208d"},
                new Object[]{0, "[127.0.0.1]:8333", "000000000000000000000000000000000000ffff7f000001208d"},
                new Object[]{2, "[etj2w3zby7hfaldy34dsuttvjtimywhvqjitk3w75ufprsqe47vr6vyd.onion]:8333", "2b71fd62fd0d04042024d3ab6f21c7ce502c78df072a4e754cd0cc58f58251356edfed0af8ca04e7eb208d"},
                new Object[]{2, "[ PeerAddress of unsupported type ]:8333", "2f29fa62fd0d040610fca6763db6183c48d0d58d902c80e1f2208d"}
        };
    }
}
