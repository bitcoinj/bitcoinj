/*
 * Copyright 2017 John L. Jegutanis
 * Copyright 2018 Andreas Schildbach
 * Copyright 2019 Tim Strasser
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

package org.bitcoinj.script;

import com.google.common.collect.Lists;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.crypto.DumpedPrivateKey;
import org.bitcoinj.crypto.ECKey;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.bitcoinj.base.BitcoinNetwork.MAINNET;
import static org.bitcoinj.script.ScriptOpCodes.OP_CHECKMULTISIG;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ScriptPatternTest {
    private List<ECKey> keys = Lists.newArrayList(new ECKey(), new ECKey(), new ECKey());

    @Test
    public void testCreateP2PKHOutputScript() {
        assertTrue(ScriptPattern.isP2PKH(
                ScriptBuilder.createP2PKHOutputScript(keys.get(0))
        ));
    }

    @Test
    public void testCreateP2SHOutputScript() {
        assertTrue(ScriptPattern.isP2SH(
                ScriptBuilder.createP2SHOutputScript(2, keys)
        ));
    }

    @Test
    public void testCreateP2PKOutputScript() {
        assertTrue(ScriptPattern.isP2PK(
                ScriptBuilder.createP2PKOutputScript(keys.get(0))
        ));
    }

    @Test
    public void testCreateP2WPKHOutputScript() {
        assertTrue(ScriptPattern.isP2WPKH(
                ScriptBuilder.createP2WPKHOutputScript(keys.get(0))
        ));
    }

    @Test
    public void testCreateP2WSHOutputScript() {
        assertTrue(ScriptPattern.isP2WSH(
                ScriptBuilder.createP2WSHOutputScript(new ScriptBuilder().build())
        ));
    }

    @Test
    public void testCreateMultiSigOutputScript() {
        assertTrue(ScriptPattern.isSentToMultisig(
                ScriptBuilder.createMultiSigOutputScript(2, keys)
        ));
    }

    @Test
    public void testIsSentToMultisigFailure() {
        // at the time this test was written, the following script would result in throwing
        // put a non OP_N opcode first and second-to-last positions
        Script evil = new ScriptBuilder()
                .op(0xff)
                .op(0xff)
                .op(0xff)
                .op(OP_CHECKMULTISIG)
                .build();
        assertFalse(ScriptPattern.isSentToMultisig(evil));
    }

    @Test
    public void testCreateOpReturnScript() {
        assertTrue(ScriptPattern.isOpReturn(
                ScriptBuilder.createOpReturnScript(new byte[10])
        ));
    }

    @Test
    public void p2shScriptHashFromKeys() {
        // import some keys from this example: https://gist.github.com/gavinandresen/3966071
        ECKey key1 = DumpedPrivateKey.fromBase58(MAINNET, "5JaTXbAUmfPYZFRwrYaALK48fN6sFJp4rHqq2QSXs8ucfpE4yQU").getKey();
        key1 = ECKey.fromPrivate(key1.getPrivKeyBytes());
        ECKey key2 = DumpedPrivateKey.fromBase58(MAINNET, "5Jb7fCeh1Wtm4yBBg3q3XbT6B525i17kVhy3vMC9AqfR6FH2qGk").getKey();
        key2 = ECKey.fromPrivate(key2.getPrivKeyBytes());
        ECKey key3 = DumpedPrivateKey.fromBase58(MAINNET, "5JFjmGo5Fww9p8gvx48qBYDJNAzR9pmH5S389axMtDyPT8ddqmw").getKey();
        key3 = ECKey.fromPrivate(key3.getPrivKeyBytes());
        List<ECKey> keys = Arrays.asList(key1, key2, key3);
        Script p2shScript = ScriptBuilder.createP2SHOutputScript(2, keys);
        byte[] p2shScriptHash = ScriptPattern.extractHashFromP2SH(p2shScript);
        assertEquals("defdb71910720a2c854529019189228b4245eddd", ByteUtils.formatHex(p2shScriptHash));
    }

    @Test
    public void isWitnessCommitment() {
        // OP_RETURN <1-byte length 36> <4-byte commitment header> <32 bytes commitment>
        String hex = "6a24aa21a9ed0000000000000000000000000000000000000000000000000000000000000000";
        Script script = Script.parse(ByteUtils.parseHex(hex));
        assertTrue(ScriptPattern.isWitnessCommitment(script));
        assertEquals(Sha256Hash.ZERO_HASH, ScriptPattern.extractWitnessCommitmentHash(script));
    }

    @Test
    public void isWitnessCommitment_tooShort() {
        // OP_RETURN <1-byte length 35> <4-byte commitment header> <31 bytes commitment>
        String hex = "6a23aa21a9ed00000000000000000000000000000000000000000000000000000000000000";
        Script script = Script.parse(ByteUtils.parseHex(hex));
        assertFalse(ScriptPattern.isWitnessCommitment(script));
    }

    @Test
    public void isWitnessCommitment_tooLong() {
        // OP_RETURN <1-byte length 37> <4-byte commitment header> <33 bytes commitment>
        String hex = "6a25aa21a9ed000000000000000000000000000000000000000000000000000000000000000000";
        Script script = Script.parse(ByteUtils.parseHex(hex));
        assertFalse(ScriptPattern.isWitnessCommitment(script));
    }

    @Test
    public void isWitnessCommitment_noOpReturn() {
        // OP_NOP <1-byte length 36> <4-byte commitment header> <32 bytes commitment>
        String hex = "6124aa21a9ed0000000000000000000000000000000000000000000000000000000000000000";
        Script script = Script.parse(ByteUtils.parseHex(hex));
        assertFalse(ScriptPattern.isWitnessCommitment(script));
    }

    @Test
    public void isWitnessCommitment_wrongCommitmentHeader() {
        // OP_RETURN <1-byte length 36> <4-byte commitment header> <32 bytes commitment>
        String hex = "6a24ffffffff0000000000000000000000000000000000000000000000000000000000000000";
        Script script = Script.parse(ByteUtils.parseHex(hex));
        assertFalse(ScriptPattern.isWitnessCommitment(script));
    }

    @Test
    public void extractWitnessCommitmentHash() {
        // OP_RETURN <1-byte length 36> <4-byte commitment header> <32 bytes commitment>
        String hex = "6a24aa21a9ed0000000000000000000000000000000000000000000000000000000000000000";
        Script script = Script.parse(ByteUtils.parseHex(hex));
        Sha256Hash hash = ScriptPattern.extractWitnessCommitmentHash(script);
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000",
                ByteUtils.formatHex(hash.getBytes()));
    }
}
