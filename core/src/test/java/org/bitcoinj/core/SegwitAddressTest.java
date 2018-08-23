/*
 * Copyright 2018 Andreas Schildbach
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Locale;

import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.Script.ScriptType;
import org.bitcoinj.script.ScriptBuilder;
import org.bitcoinj.script.ScriptPattern;
import org.junit.Test;

import com.google.common.base.MoreObjects;

public class SegwitAddressTest {
    private static final MainNetParams MAINNET = MainNetParams.get();
    private static final TestNet3Params TESTNET = TestNet3Params.get();

    @Test
    public void example_p2wpkh_mainnet() {
        String bech32 = "btg1qctd9khgd8er4j36f0hj3jw9a3cq3sy0saqs267";

        SegwitAddress address = SegwitAddress.fromBech32(MAINNET, bech32);

        assertEquals(MAINNET, address.params);
        assertEquals("0014c2da5b5d0d3e475947497de51938bd8e011811f0",
                Utils.HEX.encode(ScriptBuilder.createOutputScript(address).getProgram()));
        assertEquals(ScriptType.P2WPKH, address.getOutputScriptType());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toBech32());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toString());
    }

    @Test
    public void example_p2wsh_mainnet() {
        String bech32 = "btg1qx4k7mcrs35zqdljewht3xe9aqlk0axm5q3p0pdd2p29e92vvhqcs58cyk2";

        SegwitAddress address = SegwitAddress.fromBech32(MAINNET, bech32);

        assertEquals(MAINNET, address.params);
        assertEquals("0020356dede0708d0406fe5975d71364bd07ecfe9b740442f0b5aa0a8b92a98cb831",
                Utils.HEX.encode(ScriptBuilder.createOutputScript(address).getProgram()));
        assertEquals(ScriptType.P2WSH, address.getOutputScriptType());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toBech32());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toString());
    }

    @Test
    public void example_p2wpkh_testnet() {
        String bech32 = "tbtg1qpmvswadxvzv63dvr0my85hq8s4w0gd0vtfkyhn";

        SegwitAddress address = SegwitAddress.fromBech32(TESTNET, bech32);

        assertEquals(TESTNET, address.params);
        assertEquals("00140ed90775a66099a8b5837ec87a5c07855cf435ec",
                Utils.HEX.encode(ScriptBuilder.createOutputScript(address).getProgram()));
        assertEquals(ScriptType.P2WPKH, address.getOutputScriptType());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toBech32());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toString());
    }

    @Test
    public void example_p2wsh_testnet() {
        String bech32 = "tbtg1qztx46dr8qwehz3zgu326urm98uj33ssj2vsr542sxrx3gqh22tnstsk546";

        SegwitAddress address = SegwitAddress.fromBech32(TESTNET, bech32);

        assertEquals(TESTNET, address.params);
        assertEquals("002012cd5d346703b3714448e455ae0f653f2518c21253203a555030cd1402ea52e7",
                Utils.HEX.encode(ScriptBuilder.createOutputScript(address).getProgram()));
        assertEquals(ScriptType.P2WSH, address.getOutputScriptType());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toBech32());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toString());
    }

    @Test
    public void validAddresses() {
        for (AddressData valid : VALID_ADDRESSES) {
            SegwitAddress address = SegwitAddress.fromBech32(null, valid.address);

            assertEquals(valid.expectedParams, address.params);
            assertEquals(valid.expectedScriptPubKey,
                    Utils.HEX.encode(ScriptBuilder.createOutputScript(address).getProgram()));
            assertEquals(valid.address.toLowerCase(Locale.ROOT), address.toBech32());
            if (valid.expectedWitnessVersion == 0) {
                Script expectedScriptPubKey = new Script(Utils.HEX.decode(valid.expectedScriptPubKey));
                assertEquals(address, SegwitAddress.fromHash(valid.expectedParams,
                        ScriptPattern.extractHashFromPayToWitnessHash(expectedScriptPubKey)));
            }
            assertEquals(valid.expectedWitnessVersion, address.getWitnessVersion());
        }
    }

    private static class AddressData {
        final String address;
        final NetworkParameters expectedParams;
        final String expectedScriptPubKey;
        final int expectedWitnessVersion;

        AddressData(String address, NetworkParameters expectedParams, String expectedScriptPubKey,
                int expectedWitnessVersion) {
            this.address = address;
            this.expectedParams = expectedParams;
            this.expectedScriptPubKey = expectedScriptPubKey;
            this.expectedWitnessVersion = expectedWitnessVersion;
        }

        @Override
        public String toString() {
            return MoreObjects.toStringHelper(this).add("address", address).add("params", expectedParams.getId())
                    .add("scriptPubKey", expectedScriptPubKey).add("witnessVersion", expectedWitnessVersion).toString();
        }
    }

    private static AddressData[] VALID_ADDRESSES = {
            new AddressData("btg1qctd9khgd8er4j36f0hj3jw9a3cq3sy0saqs267", MAINNET,
                    "0014c2da5b5d0d3e475947497de51938bd8e011811f0", 0),
            new AddressData("tbtg1qztx46dr8qwehz3zgu326urm98uj33ssj2vsr542sxrx3gqh22tnstsk546", TESTNET,
                    "002012cd5d346703b3714448e455ae0f653f2518c21253203a555030cd1402ea52e7", 0),
            new AddressData("btg1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kc36v4c", MAINNET,
                    "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6", 1),
            new AddressData("btg1sw50q305ens", MAINNET, "6002751e", 16),
            new AddressData("btg1zw508d6qejxtdg4y5r3zarvaryv2eet8g", MAINNET, "5210751e76e8199196d454941c45d1b3a323", 2),
            new AddressData("tbtg1qu97qep3srh2mntkc8fln2trc56erpahk2zvpf4z65sfv6adwfv8qex4t56", TESTNET,
                    "0020e17c0c86301dd5b9aed83a7f352c78a6b230f6f6509814d45aa412cd75ae4b0e", 0) };

    @Test
    public void invalidAddresses() {
        for (String invalid : INVALID_ADDRESSES) {
            try {
                SegwitAddress.fromBech32(null, invalid);
                fail(invalid);
            } catch (AddressFormatException x) {
                // expected
            }
        }
    }

    private static String[] INVALID_ADDRESSES = { //
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", // Invalid human-readable part
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", // Invalid checksum
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", // Invalid witness version
            "bc1rw5uspcuh", // Invalid program length
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90", // Invalid program length
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", // Invalid program length for witness version 0 (per BIP141)
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", // Mixed case
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", // Zero padding of more than 4 bits
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv", // Non-zero padding in 8-to-5 conversion
            "bc1gmk9yu", // Empty data section
    };

    @Test(expected = AddressFormatException.InvalidDataLength.class)
    public void fromBech32_version0_invalidLength() {
        SegwitAddress.fromBech32(null, "btg1zw508d6qejxtdg4y5r3zarvaryv2eet8g1");
    }

    @Test(expected = AddressFormatException.InvalidDataLength.class)
    public void fromBech32_tooShort() {
        SegwitAddress.fromBech32(null, "btg1sw50q305ens1");
    }

    @Test(expected = AddressFormatException.InvalidDataLength.class)
    public void fromBech32_tooLong() {
        SegwitAddress.fromBech32(null, "btg1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kc36v4c1");
    }

    @Test(expected = AddressFormatException.InvalidPrefix.class)
    public void fromBech32_invalidHrp() {
        SegwitAddress.fromBech32(null, "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty");
    }

    @Test(expected = AddressFormatException.WrongNetwork.class)
    public void fromBech32_wrongNetwork() {
        SegwitAddress.fromBech32(TESTNET, "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj");
    }

    @Test
    public void testJavaSerialization() throws Exception {
        SegwitAddress address = SegwitAddress.fromBech32(null, "btg1sw50q305ens");

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        new ObjectOutputStream(os).writeObject(address);
        PrefixedChecksummedBytes addressCopy = (PrefixedChecksummedBytes) new ObjectInputStream(
                new ByteArrayInputStream(os.toByteArray())).readObject();

        assertEquals(address, addressCopy);
        assertEquals(address.params, addressCopy.params);
        assertArrayEquals(address.bytes, addressCopy.bytes);
    }
}
