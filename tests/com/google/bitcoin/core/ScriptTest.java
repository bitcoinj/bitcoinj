/**
 * Copyright 2011 Google Inc.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ScriptTest {
    // From tx 05e04c26c12fe408a3c1b71aa7996403f6acad1045252b1c62e055496f4d2cb1 on the testnet.

    static final String sigProg = "473    04402202b4da291cc39faf8433911988f9f49fc5c995812ca2f94db61468839c228c3e90220628bff3ff32ec95825092fa051cba28558a981fcf59ce184b14f2e215e69106701410414b38f4be3bb9fa0f4f32b74af07152b2f2f630bc02122a491137b6c523e46f18a0d5034418966f93dfc37cc3739ef7b2007213a302b7fba161557f4ad644a1c";

    static final String pubkeyProg = "76a91433e81a941e64cda12c6a299ed322ddbdd03f8d0e88ac";


    static final NetworkParameters params = NetworkParameters.testNet();

    @Test
    public void testScriptSig() throws Exception {
        byte[] sigProgBytes = Hex.decode(sigProg);
        Script script = new Script(params, sigProgBytes, 0, sigProgBytes.length);
        // Test we can extract the from address.
        byte[] hash160 = Utils.sha256hash160(script.getPubKey());
        Address a = new Address(params, hash160);
        assertEquals("mkFQohBpy2HDXrCwyMrYL5RtfrmeiuuPY2", a.toString());
    }

    @Test
    public void testScriptPubKey() throws Exception {
        // Check we can extract the to address
        byte[] pubkeyBytes = Hex.decode(pubkeyProg);
        Script pubkey = new Script(params, pubkeyBytes, 0, pubkeyBytes.length);
        Address toAddr = new Address(params, pubkey.getPubKeyHash());
        assertEquals("mkFQohBpy2HDXrCwyMrYL5RtfrmeiuuPY2", toAddr.toString());
    }

    @Test
    public void testIp() throws Exception {
        byte[] bytes = Hex.decode("41043e96222332ea7848323c08116dddafbfa917b8e37f0bdf63841628267148588a09a43540942d58d49717ad3fabfe14978cf4f0a8b84d2435dad16e9aa4d7f935ac");
        Script s = new Script(params, bytes, 0, bytes.length);
        assertTrue(s.isSentToIP());
    }
}
