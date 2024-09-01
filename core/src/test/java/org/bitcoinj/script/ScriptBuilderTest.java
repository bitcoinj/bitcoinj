/*
 * Copyright 2018 Nicola Atzei
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

import org.bitcoinj.base.Address;
import org.bitcoinj.base.AddressParser;
import org.bitcoinj.base.LegacyAddress;
import org.bitcoinj.base.SegwitAddress;
import org.bitcoinj.base.internal.ByteUtils;
import org.bitcoinj.test.support.AddressData;

import org.junit.Test;

import static org.bitcoinj.base.BitcoinNetwork.MAINNET;
import static org.bitcoinj.base.BitcoinNetwork.REGTEST;
import static org.bitcoinj.base.BitcoinNetwork.TESTNET;
import static org.bitcoinj.script.ScriptOpCodes.OP_FALSE;
import static org.bitcoinj.script.ScriptOpCodes.OP_TRUE;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class ScriptBuilderTest {

    @Test
    public void testNumber() {
        for (int i = -100; i <= 100; i++) {
            Script s = new ScriptBuilder().number(i).build();
            for (ScriptChunk ch : s.chunks()) {
                assertTrue(Integer.toString(i), ch.isShortestPossiblePushData());
            }
        }
    }

    @Test
    public void numberBuilderZero() {
        // Test encoding of zero, which should result in an opcode
        final ScriptBuilder builder = new ScriptBuilder();

        // 0 should encode directly to 0
        builder.number(0);
        assertArrayEquals(new byte[] {
            0x00         // Pushed data
        }, builder.build().program());
    }

    @Test
    public void numberBuilderPositiveOpCode() {
        final ScriptBuilder builder = new ScriptBuilder();

        builder.number(5);
        assertArrayEquals(new byte[] {
            0x55         // Pushed data
        }, builder.build().program());
    }

    @Test
    public void numberBuilderBigNum() {
        ScriptBuilder builder = new ScriptBuilder();
        // 21066 should take up three bytes including the length byte
        // at the start

        builder.number(0x524a);
        assertArrayEquals(new byte[] {
            0x02,             // Length of the pushed data
            0x4a, 0x52        // Pushed data
        }, builder.build().program());

        // Test the trimming code ignores zeroes in the middle
        builder = new ScriptBuilder();
        builder.number(0x110011);
        assertEquals(4, builder.build().program().length);

        // Check encoding of a value where signed/unsigned encoding differs
        // because the most significant byte is 0x80, and therefore a
        // sign byte has to be added to the end for the signed encoding.
        builder = new ScriptBuilder();
        builder.number(0x8000);
        assertArrayEquals(new byte[] {
            0x03,             // Length of the pushed data
            0x00, (byte) 0x80, 0x00  // Pushed data
        }, builder.build().program());
    }

    @Test
    public void numberBuilderNegative() {
        // Check encoding of a negative value
        final ScriptBuilder builder = new ScriptBuilder();
        builder.number(-5);
        assertArrayEquals(new byte[] {
            0x01,        // Length of the pushed data
            ((byte) 133) // Pushed data
        }, builder.build().program());
    }

    @Test
    public void numberBuilder16() {
        ScriptBuilder builder = new ScriptBuilder();
        // Numbers greater than 16 must be encoded with PUSHDATA
        builder.number(15).number(16).number(17);
        builder.number(0, 17).number(1, 16).number(2, 15);
        Script script = builder.build();
        assertEquals("PUSHDATA(1)[11] 16 15 15 16 PUSHDATA(1)[11]", script.toString());
    }

    @Test
    public void testOpTrue() {
        byte[] expected = new byte[] { OP_TRUE };
        byte[] s = new ScriptBuilder().opTrue().build().program();
        assertArrayEquals(expected, s);
    }

    @Test
    public void testOpFalse() {
        byte[] expected = new byte[] { OP_FALSE };
        byte[] s = new ScriptBuilder().opFalse().build().program();
        assertArrayEquals(expected, s);
    }

    @Test
    public void p2shAddressTest() {
        // Test that we can convert a redeem script to an address
        byte[] redeemScriptHex = ByteUtils.parseHex("2ac4b0b501117cc8119c5797b519538d4942e90e");
        LegacyAddress c = LegacyAddress.fromScriptHash(MAINNET,
                ScriptPattern.extractHashFromP2SH(ScriptBuilder.createP2SHOutputScript(redeemScriptHex)));
        assertEquals("35b9vsyH1KoFT5a5KtrKusaCcPLkiSo1tU", c.toString());
    }

    @Test
    public void example_p2wpkh_mainnet() {
        String bech32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

        SegwitAddress address = SegwitAddress.fromBech32(bech32, MAINNET);

        assertEquals("0014751e76e8199196d454941c45d1b3a323f1433bd6",
                ByteUtils.formatHex(ScriptBuilder.createOutputScript(address).program()));
    }

    @Test
    public void example_p2wsh_mainnet() {
        String bech32 = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";

        SegwitAddress address = SegwitAddress.fromBech32(bech32, MAINNET);

        assertEquals("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
                ByteUtils.formatHex(ScriptBuilder.createOutputScript(address).program()));
    }

    @Test
    public void example_p2wpkh_testnet() {
        String bech32 = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

        SegwitAddress address = SegwitAddress.fromBech32(bech32, TESTNET);

        assertEquals("0014751e76e8199196d454941c45d1b3a323f1433bd6",
                ByteUtils.formatHex(ScriptBuilder.createOutputScript(address).program()));
    }

    @Test
    public void example_p2wpkh_regtest() {
        String bcrt1_bech32 = "bcrt1qspfueag7fvty7m8htuzare3xs898zvh30fttu2";

        SegwitAddress address = SegwitAddress.fromBech32(bcrt1_bech32, REGTEST);

        assertEquals("00148053ccf51e4b164f6cf75f05d1e62681ca7132f1",
                ByteUtils.formatHex(ScriptBuilder.createOutputScript(address).program()));
    }

    @Test
    public void example_p2wpkh_regtest_any_network() {
        AddressParser addressParser = AddressParser.getDefault();

        String bcrt1_bech32 = "bcrt1qspfueag7fvty7m8htuzare3xs898zvh30fttu2";

        Address address = addressParser.parseAddress(bcrt1_bech32);

        assertEquals("00148053ccf51e4b164f6cf75f05d1e62681ca7132f1",
                ByteUtils.formatHex(ScriptBuilder.createOutputScript(address).program()));
    }

    @Test
    public void example_p2wsh_testnet() {
        String bech32 = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";

        SegwitAddress address = SegwitAddress.fromBech32(bech32, TESTNET);

        assertEquals("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
                ByteUtils.formatHex(ScriptBuilder.createOutputScript(address).program()));
    }

    @Test
    public void validAddresses() {
        AddressParser addressParser = AddressParser.getDefault();

        for (AddressData valid : AddressData.VALID_ADDRESSES) {
            SegwitAddress address = (SegwitAddress) addressParser.parseAddress(valid.address);

            assertEquals(valid.expectedScriptPubKey,
                    ByteUtils.formatHex(ScriptBuilder.createOutputScript(address).program()));
            if (valid.expectedWitnessVersion == 0) {
                Script expectedScriptPubKey = Script.parse(ByteUtils.parseHex(valid.expectedScriptPubKey));
                assertEquals(address, SegwitAddress.fromHash(valid.expectedNetwork,
                        ScriptPattern.extractHashFromP2WH(expectedScriptPubKey)));
            }
        }
    }
}
