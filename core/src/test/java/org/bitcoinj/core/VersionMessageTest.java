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

import org.bitcoinj.params.UnitTestParams;
import org.junit.Test;

import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class VersionMessageTest {
    @Test
    // Test that we can decode version messages which miss data which some old nodes may not include
    public void testDecode() throws Exception {
        NetworkParameters params = UnitTestParams.get();

        VersionMessage ver = new VersionMessage(params, HEX.decode("7111010000000000000000003334a85500000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d00000000000000000f2f626974636f696e6a3a302e31332f0004000000"));
        assertFalse(ver.relayTxesBeforeFilter);
        assertEquals(1024, ver.bestHeight);
        assertEquals("/bitcoinj:0.13/", ver.subVer);

        ver = new VersionMessage(params, HEX.decode("711101000000000000000000a634a85500000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d00000000000000000f2f626974636f696e6a3a302e31332f0004000001"));
        assertTrue(ver.relayTxesBeforeFilter);
        assertEquals(1024, ver.bestHeight);
        assertEquals("/bitcoinj:0.13/", ver.subVer);

        ver = new VersionMessage(params, HEX.decode("711101000000000000000000c334a85500000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d00000000000000000f2f626974636f696e6a3a302e31332f0000000001"));
        assertTrue(ver.relayTxesBeforeFilter);
        assertEquals(0, ver.bestHeight);
        assertEquals("/bitcoinj:0.13/", ver.subVer);

        ver = new VersionMessage(params, HEX.decode("71110100000000000000000048e5e95000000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d0000000000000000"));
        assertTrue(ver.relayTxesBeforeFilter);
        assertEquals(0, ver.bestHeight);
        assertEquals("", ver.subVer);
    }
}
