/*
 * Copyright by the original author or authors.
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

import org.bitcoinj.params.UnitTestParams;
import org.junit.Test;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.util.List;

import static org.bitcoinj.base.utils.ByteUtils.HEX;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class AddressV2MessageTest {

    private static final NetworkParameters UNITTEST = UnitTestParams.get();
    // mostly copied from src/test/netbase_tests.cpp#stream_addrv2_hex and src/test/net_tests.cpp
    private static final String MESSAGE_HEX =
            "05" // number of entries

                    + "61bc6649" // time, Fri Jan  9 02:54:25 UTC 2009
                    + "00" // service flags, COMPACTSIZE(NODE_NONE)
                    + "01" // network id, IPv4
                    + "04" // address length, COMPACTSIZE(4)
                    + "00000001" // address
                    + "0000" // port

                    + "79627683" // time, Tue Nov 22 11:22:33 UTC 2039
                    + "01" // service flags, COMPACTSIZE(NODE_NETWORK)
                    + "02" // network id, IPv6
                    + "10" // address length, COMPACTSIZE(16)
                    + "00000000000000000000000000000001" // address
                    + "00f1" // port

                    + "ffffffff" // time, Sun Feb  7 06:28:15 UTC 2106
                    + "fd4804" // service flags, COMPACTSIZE(NODE_WITNESS | NODE_COMPACT_FILTERS | NODE_NETWORK_LIMITED)
                    + "02" // network id, IPv6
                    + "10" // address length, COMPACTSIZE(16)
                    + "00000000000000000000000000000001" // address
                    + "f1f2" // port

                    + "00000000" // time
                    + "00" // service flags, COMPACTSIZE(NODE_NONE)
                    + "03" // network id, TORv2
                    + "0a" // address length, COMPACTSIZE(10)
                    + "f1f2f3f4f5f6f7f8f9fa" // address
                    + "0000" // port

                    + "00000000" // time
                    + "00" // service flags, COMPACTSIZE(NODE_NONE)
                    + "04" // network id, TORv3
                    + "20"// address length, COMPACTSIZE(32)
                    + "53cd5648488c4707914182655b7664034e09e66f7e8cbf1084e654eb56c5bd88" // address
                    + "0000"; // port

    @Test
    public void roundtrip() {
        AddressMessage message = new AddressV2Message(UNITTEST, HEX.decode(MESSAGE_HEX));

        List<PeerAddress> addresses = message.getAddresses();
        assertEquals(5, addresses.size());
        PeerAddress a0 = addresses.get(0);
        assertEquals("2009-01-09T02:54:25Z", Utils.dateTimeFormat(a0.getTime() * 1000));
        assertEquals(0, a0.getServices().intValue());
        assertTrue(a0.getAddr() instanceof Inet4Address);
        assertEquals("0.0.0.1", a0.getAddr().getHostAddress());
        assertNull(a0.getHostname());
        assertEquals(0, a0.getPort());
        PeerAddress a1 = addresses.get(1);
        assertEquals("2039-11-22T11:22:33Z", Utils.dateTimeFormat(a1.getTime() * 1000));
        assertEquals(VersionMessage.NODE_NETWORK, a1.getServices().intValue());
        assertTrue(a1.getAddr() instanceof Inet6Address);
        assertEquals("0:0:0:0:0:0:0:1", a1.getAddr().getHostAddress());
        assertNull(a1.getHostname());
        assertEquals(0xf1, a1.getPort());
        PeerAddress a2 = addresses.get(2);
        assertEquals("2106-02-07T06:28:15Z", Utils.dateTimeFormat(a2.getTime() * 1000));
        assertEquals(VersionMessage.NODE_WITNESS | 1 << 6 /* NODE_COMPACT_FILTERS  */
                | VersionMessage.NODE_NETWORK_LIMITED, a2.getServices().intValue());
        assertTrue(a2.getAddr() instanceof Inet6Address);
        assertEquals("0:0:0:0:0:0:0:1", a2.getAddr().getHostAddress());
        assertNull(a2.getHostname());
        assertEquals(0xf1f2, a2.getPort());
        PeerAddress a3 = addresses.get(3);
        assertEquals("1970-01-01T00:00:00Z", Utils.dateTimeFormat(a3.getTime() * 1000));
        assertEquals(0, a3.getServices().intValue());
        assertNull(a3.getAddr());
        assertEquals("6hzph5hv6337r6p2.onion", a3.getHostname());
        assertEquals(0, a3.getPort());
        PeerAddress a4 = addresses.get(4);
        assertEquals("1970-01-01T00:00:00Z", Utils.dateTimeFormat(a4.getTime() * 1000));
        assertEquals(0, a4.getServices().intValue());
        assertNull(a4.getAddr());
        assertEquals("kpgvmscirrdqpekbqjsvw5teanhatztpp2gl6eee4zkowvwfxwenqaid.onion", a4.getHostname());
        assertEquals(0, a4.getPort());

        assertEquals(MESSAGE_HEX, HEX.encode(message.bitcoinSerialize()));
    }
}
