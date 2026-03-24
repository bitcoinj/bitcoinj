/*
 * Copyright 2012 Matt Corallo
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

import org.bitcoinj.params.TestNet3Params;
import org.junit.Test;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.time.Instant;

import org.bitcoinj.base.internal.ByteUtils;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

public class VersionMessageTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();
    private static final Inet4Address LOCALHOST_IPV4ADDR = getLocalhostAddr();

    private static Inet4Address getLocalhostAddr() {
        try {
            return (Inet4Address) InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testConstructor() {
        VersionMessage versionMessage = new VersionMessage(TESTNET, 0);
        assertEquals(LOCALHOST_IPV4ADDR, versionMessage.receivingAddr().getAddress());
        assertEquals(TESTNET.getPort(), versionMessage.receivingAddr().getPort());
    }

    @Test
    public void decode_noRelay_bestHeight_subVer() {
        String hex = "7111010000000000000000003334a85500000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d00000000000000000f2f626974636f696e6a3a302e31332f0004000000";
        VersionMessage ver = VersionMessage.read(ByteBuffer.wrap(ByteUtils.parseHex(hex)));
        assertFalse(ver.relayTxesBeforeFilter());
        assertEquals(1024, ver.bestHeight());
        assertEquals("/bitcoinj:0.13/", ver.subVer());
    }

    @Test
    public void decode_relay_bestHeight_subVer() {
        String hex = "711101000000000000000000a634a85500000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d00000000000000000f2f626974636f696e6a3a302e31332f0004000001";
        VersionMessage ver = VersionMessage.read(ByteBuffer.wrap(ByteUtils.parseHex(hex)));
        assertTrue(ver.relayTxesBeforeFilter());
        assertEquals(1024, ver.bestHeight());
        assertEquals("/bitcoinj:0.13/", ver.subVer());
    }

    @Test
    public void decode_relay_noBestHeight_subVer() {
        String hex = "711101000000000000000000c334a85500000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d00000000000000000f2f626974636f696e6a3a302e31332f0000000001";
        VersionMessage ver = VersionMessage.read(ByteBuffer.wrap(ByteUtils.parseHex(hex)));
        assertTrue(ver.relayTxesBeforeFilter());
        assertEquals(0, ver.bestHeight());
        assertEquals("/bitcoinj:0.13/", ver.subVer());
    }

    @Test(expected = ProtocolException.class)
    public void decode_relay_noBestHeight_noSubVer() {
        String hex = "00000000000000000000000048e5e95000000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d0000000000000000";
        VersionMessage.read(ByteBuffer.wrap(ByteUtils.parseHex(hex)));
    }

    @Test
    public void roundTrip_ipv4() throws Exception {
        VersionMessage ver = new VersionMessage.Builder(TESTNET, 1234)
                .time(Instant.ofEpochSecond(23456))
                .subVer("/bitcoinj/")
                .localServices(Services.of(1))
                .receivingAddr(new InetSocketAddress(InetAddress.getByName("4.3.2.1"), 8333))
                .build();
        byte[] serialized = ver.serialize();
        VersionMessage ver2 = VersionMessage.read(ByteBuffer.wrap(serialized));
        assertEquals(1234, ver2.bestHeight());
        assertEquals(Instant.ofEpochSecond(23456), ver2.time());
        assertEquals("/bitcoinj/", ver2.subVer());
        assertEquals(ProtocolVersion.CURRENT.intValue(), ver2.clientVersion());
        assertEquals(1, ver2.localServices().bits());
        assertEquals("4.3.2.1", ver2.receivingAddr().getHostName());
        assertEquals(8333, ver2.receivingAddr().getPort());
    }

    @Test
    public void roundTrip_ipv6() throws Exception {
        VersionMessage ver = new VersionMessage.Builder(TESTNET, 1234)
                .time(Instant.ofEpochSecond(23456))
                .subVer("/bitcoinj/")
                .localServices(Services.of(1))
                .receivingAddr(new InetSocketAddress(InetAddress.getByName("2002:db8:85a3:0:0:8a2e:370:7335"), 8333))
                .build();
        byte[] serialized = ver.serialize();
        VersionMessage ver2 = VersionMessage.read(ByteBuffer.wrap(serialized));
        assertEquals(1234, ver2.bestHeight());
        assertEquals(Instant.ofEpochSecond(23456), ver2.time());
        assertEquals("/bitcoinj/", ver2.subVer());
        assertEquals(ProtocolVersion.CURRENT.intValue(), ver2.clientVersion());
        assertEquals(1, ver2.localServices().bits());
        assertEquals("2002:db8:85a3:0:0:8a2e:370:7335", ver2.receivingAddr().getHostName());
        assertEquals(8333, ver2.receivingAddr().getPort());
    }

    @Test
    public void testBuilderFromParams() {
        // Verify Builder defaults match constructor, and accessors work
        VersionMessage fromCtor = new VersionMessage(TESTNET, 500);
        VersionMessage fromBuilder = new VersionMessage.Builder(TESTNET, 500)
                .time(fromCtor.time()).build();
        assertEquals(fromCtor.clientVersion(), fromBuilder.clientVersion());
        assertEquals(fromCtor.localServices(), fromBuilder.localServices());
        assertEquals(fromCtor.receivingServices(), fromBuilder.receivingServices());
        assertEquals(fromCtor.subVer(), fromBuilder.subVer());
        assertEquals(fromCtor.bestHeight(), fromBuilder.bestHeight());
        assertEquals(fromCtor.relayTxesBeforeFilter(), fromBuilder.relayTxesBeforeFilter());
        // Verify custom values via Builder
        VersionMessage custom = new VersionMessage.Builder(TESTNET, 500)
                .clientVersion(70015)
                .localServices(Services.of(Services.NODE_NETWORK | Services.NODE_WITNESS))
                .relayTxesBeforeFilter(false)
                .build();
        assertEquals(70015, custom.clientVersion());
        assertTrue(custom.services().has(Services.NODE_NETWORK));
        assertEquals(500, custom.bestHeight());
        assertFalse(custom.relayTxesBeforeFilter());
    }

    @Test
    public void testBuilderCopyWithOverrides() throws Exception {
        // Build a fully-customized message
        VersionMessage original = new VersionMessage.Builder(TESTNET, 100)
                .clientVersion(70015)
                .localServices(Services.of(Services.NODE_NETWORK))
                .time(Instant.ofEpochSecond(12345))
                .receivingServices(Services.of(Services.NODE_BLOOM))
                .receivingAddr(new InetSocketAddress(InetAddress.getByName("4.3.2.1"), 8333))
                .subVer("/test:1.0/")
                .relayTxesBeforeFilter(false)
                .build();
        // Copy preserves all fields
        VersionMessage copy = new VersionMessage.Builder(original).build();
        assertEquals(original, copy);
        // Copy with overrides changes only specified fields
        VersionMessage modified = new VersionMessage.Builder(original)
                .bestHeight(200).relayTxesBeforeFilter(true).build();
        assertEquals(200, modified.bestHeight());
        assertTrue(modified.relayTxesBeforeFilter());
        assertEquals(original.clientVersion(), modified.clientVersion());
        assertEquals(original.subVer(), modified.subVer());
        assertEquals(100, original.bestHeight()); // original unchanged
    }

    @Test
    public void testAppendToSubVerReturnsNewInstance() {
        VersionMessage vm1 = new VersionMessage(TESTNET, 0);
        VersionMessage vm2 = vm1.appendToSubVer("MyApp", "1.0", null);
        assertNotSame(vm1, vm2);
        assertEquals(VersionMessage.LIBRARY_SUBVER, vm1.subVer()); // original unchanged
        assertTrue(vm2.subVer().contains("MyApp:1.0"));
    }

    @Test
    public void testSerializeDeserializeRoundTrip() {
        VersionMessage original = new VersionMessage.Builder(TESTNET, 830000)
                .localServices(Services.of(Services.NODE_NETWORK | Services.NODE_WITNESS))
                .time(Instant.ofEpochSecond(1700000000))
                .receivingServices(Services.of(Services.NODE_BLOOM))
                .receivingAddr(new InetSocketAddress(LOCALHOST_IPV4ADDR, 18333))
                .subVer("/bitcoinj:0.18-SNAPSHOT/TestApp:1.0/")
                .relayTxesBeforeFilter(false)
                .build();
        VersionMessage rt = VersionMessage.read(ByteBuffer.wrap(original.serialize()));
        assertEquals(original.clientVersion(), rt.clientVersion());
        assertEquals(original.localServices(), rt.localServices());
        assertEquals(original.time(), rt.time());
        assertEquals(original.receivingServices(), rt.receivingServices());
        assertEquals(original.receivingAddr(), rt.receivingAddr());
        assertEquals(original.subVer(), rt.subVer());
        assertEquals(original.bestHeight(), rt.bestHeight());
        assertEquals(original.relayTxesBeforeFilter(), rt.relayTxesBeforeFilter());
    }
}
