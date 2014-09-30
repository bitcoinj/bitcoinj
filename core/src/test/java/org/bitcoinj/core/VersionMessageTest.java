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
import static org.junit.Assert.assertTrue;

public class VersionMessageTest {
    @Test
    // Test that we can decode version messages which miss data which some old nodes may not include
    public void testDecode() throws Exception {
        NetworkParameters params = UnitTestParams.get();
        
        VersionMessage ver = new VersionMessage(params, HEX.decode("71110100000000000000000048e5e95000000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d0000000000000000172f426974436f696e4a3a302e372d534e415053484f542f0004000000"));
        assertTrue(!ver.relayTxesBeforeFilter);
        assertTrue(ver.bestHeight == 1024);
        assertTrue(ver.subVer.equals("/BitCoinJ:0.7-SNAPSHOT/"));
        
        ver = new VersionMessage(params, HEX.decode("71110100000000000000000048e5e95000000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d0000000000000000172f426974436f696e4a3a302e372d534e415053484f542f00040000"));
        assertTrue(ver.relayTxesBeforeFilter);
        assertTrue(ver.bestHeight == 1024);
        assertTrue(ver.subVer.equals("/BitCoinJ:0.7-SNAPSHOT/"));
        
        ver = new VersionMessage(params, HEX.decode("71110100000000000000000048e5e95000000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d0000000000000000172f426974436f696e4a3a302e372d534e415053484f542f"));
        assertTrue(ver.relayTxesBeforeFilter);
        assertTrue(ver.bestHeight == 0);
        assertTrue(ver.subVer.equals("/BitCoinJ:0.7-SNAPSHOT/"));
        
        ver = new VersionMessage(params, HEX.decode("71110100000000000000000048e5e95000000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d0000000000000000"));
        assertTrue(ver.relayTxesBeforeFilter);
        assertTrue(ver.bestHeight == 0);
        assertTrue(ver.subVer.equals(""));
    }
}
