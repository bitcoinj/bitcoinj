package com.google.bitcoin.core;

import com.google.bitcoin.params.UnitTestParams;
import org.junit.Test;
import org.spongycastle.util.encoders.Hex;

import static org.junit.Assert.assertTrue;

public class VersionMessageTest {
    @Test
    // Test that we can decode version messages which miss data which some old nodes may not include
    public void testDecode() throws Exception {
        NetworkParameters params = UnitTestParams.get();
        
        VersionMessage ver = new VersionMessage(params, Hex.decode("71110100000000000000000048e5e95000000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d0000000000000000172f426974436f696e4a3a302e372d534e415053484f542f0004000000"));
        assertTrue(!ver.relayTxesBeforeFilter);
        assertTrue(ver.bestHeight == 1024);
        assertTrue(ver.subVer.equals("/BitCoinJ:0.7-SNAPSHOT/"));
        
        ver = new VersionMessage(params, Hex.decode("71110100000000000000000048e5e95000000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d0000000000000000172f426974436f696e4a3a302e372d534e415053484f542f00040000"));
        assertTrue(ver.relayTxesBeforeFilter);
        assertTrue(ver.bestHeight == 1024);
        assertTrue(ver.subVer.equals("/BitCoinJ:0.7-SNAPSHOT/"));
        
        ver = new VersionMessage(params, Hex.decode("71110100000000000000000048e5e95000000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d0000000000000000172f426974436f696e4a3a302e372d534e415053484f542f"));
        assertTrue(ver.relayTxesBeforeFilter);
        assertTrue(ver.bestHeight == 0);
        assertTrue(ver.subVer.equals("/BitCoinJ:0.7-SNAPSHOT/"));
        
        ver = new VersionMessage(params, Hex.decode("71110100000000000000000048e5e95000000000000000000000000000000000000000000000ffff7f000001479d000000000000000000000000000000000000ffff7f000001479d0000000000000000"));
        assertTrue(ver.relayTxesBeforeFilter);
        assertTrue(ver.bestHeight == 0);
        assertTrue(ver.subVer.equals(""));
    }
}
