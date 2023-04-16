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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.time.Instant;

import org.bitcoinj.base.internal.ByteUtils;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class VersionMessageTest {
    private static final NetworkParameters TESTNET = TestNet3Params.get();

    @Test
    public void decode_noRelay_bestHeight_subVer() {
        // Test that we can decode version messages which miss data which some old nodes may not include
        String hex = "7111010000000000000000003334a85500000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d00000000000000000f2f626974636f696e6a3a302e31332f0004000000";
        VersionMessage ver = VersionMessage.read(ByteBuffer.wrap(ByteUtils.parseHex(hex)));
        assertFalse(ver.relayTxesBeforeFilter);
        assertEquals(1024, ver.bestHeight);
        assertEquals("/bitcoinj:0.13/", ver.subVer);
    }

    @Test
    public void decode_relay_bestHeight_subVer() {
        String hex = "711101000000000000000000a634a85500000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d00000000000000000f2f626974636f696e6a3a302e31332f0004000001";
        VersionMessage ver = VersionMessage.read(ByteBuffer.wrap(ByteUtils.parseHex(hex)));
        assertTrue(ver.relayTxesBeforeFilter);
        assertEquals(1024, ver.bestHeight);
        assertEquals("/bitcoinj:0.13/", ver.subVer);
    }

    @Test
    public void decode_relay_noBestHeight_subVer() {
        String hex = "711101000000000000000000c334a85500000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d00000000000000000f2f626974636f696e6a3a302e31332f0000000001";
        VersionMessage ver = VersionMessage.read(ByteBuffer.wrap(ByteUtils.parseHex(hex)));
        assertTrue(ver.relayTxesBeforeFilter);
        assertEquals(0, ver.bestHeight);
        assertEquals("/bitcoinj:0.13/", ver.subVer);
    }

    @Test(expected = ProtocolException.class)
    public void decode_relay_noBestHeight_noSubVer() {
        String hex = "00000000000000000000000048e5e95000000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d0000000000000000";
        VersionMessage ver = VersionMessage.read(ByteBuffer.wrap(ByteUtils.parseHex(hex)));
    }

    @Test
    public void roundTrip_ipv4() throws Exception {
        VersionMessage ver = new VersionMessage(TESTNET, 1234);
        ver.time = Instant.ofEpochSecond(23456);
        ver.subVer = "/bitcoinj/";
        ver.localServices = Services.of(1);
        ver.receivingAddr = new InetSocketAddress(InetAddress.getByName("4.3.2.1"), 8333);
        byte[] serialized = ver.serialize();
        VersionMessage ver2 = VersionMessage.read(ByteBuffer.wrap(serialized));
        assertEquals(1234, ver2.bestHeight);
        assertEquals(Instant.ofEpochSecond(23456), ver2.time);
        assertEquals("/bitcoinj/", ver2.subVer);
        assertEquals(ProtocolVersion.CURRENT.intValue(), ver2.clientVersion);
        assertEquals(1, ver2.localServices.bits());
        assertEquals("4.3.2.1", ver2.receivingAddr.getHostName());
        assertEquals(8333, ver2.receivingAddr.getPort());
    }

    @Test
    public void roundTrip_ipv6() throws Exception {
        VersionMessage ver = new VersionMessage(TESTNET, 1234);
        ver.time = Instant.ofEpochSecond(23456);
        ver.subVer = "/bitcoinj/";
        ver.localServices = Services.of(1);
        ver.receivingAddr = new InetSocketAddress(InetAddress.getByName("2002:db8:85a3:0:0:8a2e:370:7335"), 8333);
        byte[] serialized = ver.serialize();
        VersionMessage ver2 = VersionMessage.read(ByteBuffer.wrap(serialized));
        assertEquals(1234, ver2.bestHeight);
        assertEquals(Instant.ofEpochSecond(23456), ver2.time);
        assertEquals("/bitcoinj/", ver2.subVer);
        assertEquals(ProtocolVersion.CURRENT.intValue(), ver2.clientVersion);
        assertEquals(1, ver2.localServices.bits());
        assertEquals("2002:db8:85a3:0:0:8a2e:370:7335", ver2.receivingAddr.getHostName());
        assertEquals(8333, ver2.receivingAddr.getPort());
    }
}
