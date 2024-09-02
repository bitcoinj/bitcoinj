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

package org.bitcoinj.base;

import nl.jqno.equalsverifier.EqualsVerifier;
import nl.jqno.equalsverifier.Warning;
import org.bitcoinj.base.exceptions.AddressFormatException;
import org.bitcoinj.test.support.AddressData;
import org.junit.Test;

import java.util.Locale;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.bitcoinj.base.BitcoinNetwork.MAINNET;
import static org.bitcoinj.base.BitcoinNetwork.TESTNET;
import static org.bitcoinj.base.BitcoinNetwork.SIGNET;
import static org.bitcoinj.base.BitcoinNetwork.REGTEST;

public class SegwitAddressTest {
    private static final AddressParser addressParser = AddressParser.getDefault();

    @Test
    public void equalsContract() {
        EqualsVerifier.forClass(SegwitAddress.class)
                .withPrefabValues(BitcoinNetwork.class, MAINNET, TESTNET)
                .suppress(Warning.NULL_FIELDS)
                .suppress(Warning.TRANSIENT_FIELDS)
                .usingGetClass()
                .verify();
    }

    @Test
    public void example_p2wpkh_mainnet() {
        String bech32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

        SegwitAddress address = SegwitAddress.fromBech32(bech32, MAINNET);

        assertEquals(MAINNET, address.network());
        assertEquals(ScriptType.P2WPKH, address.getOutputScriptType());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toBech32());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toString());
    }

    @Test
    public void example_p2wsh_mainnet() {
        String bech32 = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";

        SegwitAddress address = SegwitAddress.fromBech32(bech32, MAINNET);

        assertEquals(MAINNET, address.network());
        assertEquals(ScriptType.P2WSH, address.getOutputScriptType());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toBech32());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toString());
    }

    @Test
    public void example_p2wpkh_testnet() {
        String bech32 = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

        SegwitAddress address = SegwitAddress.fromBech32(bech32, TESTNET);

        assertEquals(TESTNET, address.network());
        assertEquals(ScriptType.P2WPKH, address.getOutputScriptType());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toBech32());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toString());
    }

    @Test
    public void equalityOfEquivalentNetworks() {
        String bech32 = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

        SegwitAddress a = SegwitAddress.fromBech32(bech32, TESTNET);
        SegwitAddress b = SegwitAddress.fromBech32(bech32, SIGNET);

        assertEquals(a, b);
        assertEquals(a.toString(), b.toString());
    }

    @Test
    public void example_p2wpkh_regtest() {
        String bcrt1_bech32 = "bcrt1qspfueag7fvty7m8htuzare3xs898zvh30fttu2";

        SegwitAddress address = SegwitAddress.fromBech32(bcrt1_bech32, REGTEST);

        assertEquals(REGTEST, address.network());
        assertEquals(ScriptType.P2WPKH, address.getOutputScriptType());
        assertEquals(bcrt1_bech32.toLowerCase(Locale.ROOT), address.toBech32());
        assertEquals(bcrt1_bech32.toLowerCase(Locale.ROOT), address.toString());
    }

    @Test
    public void example_p2wpkh_regtest_any_network() {
        String bcrt1_bech32 = "bcrt1qspfueag7fvty7m8htuzare3xs898zvh30fttu2";

        Address address = addressParser.parseAddress(bcrt1_bech32);

        assertEquals(REGTEST, address.network());
        assertEquals(ScriptType.P2WPKH, address.getOutputScriptType());
        assertEquals(bcrt1_bech32.toLowerCase(Locale.ROOT), ((SegwitAddress)address).toBech32());
        assertEquals(bcrt1_bech32.toLowerCase(Locale.ROOT), address.toString());
    }

    @Test
    public void example_p2wsh_testnet() {
        String bech32 = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";

        SegwitAddress address = SegwitAddress.fromBech32(bech32, TESTNET);

        assertEquals(TESTNET, address.network());
        assertEquals(ScriptType.P2WSH, address.getOutputScriptType());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toBech32());
        assertEquals(bech32.toLowerCase(Locale.ROOT), address.toString());
    }

    @Test
    public void validAddresses() {
        for (AddressData valid : AddressData.VALID_ADDRESSES) {
            SegwitAddress address = (SegwitAddress) addressParser.parseAddress(valid.address);

            assertEquals(valid.expectedNetwork, address.network());
            assertEquals(valid.address.toLowerCase(Locale.ROOT), address.toBech32());
            assertEquals(valid.expectedWitnessVersion, address.getWitnessVersion());
        }
    }

    @Test
    public void invalidAddresses() {
        for (String invalid : AddressData.INVALID_ADDRESSES) {
            try {
                addressParser.parseAddress(invalid);
                fail(invalid);
            } catch (AddressFormatException x) {
                // expected
            }
        }
    }

    @Test(expected = AddressFormatException.InvalidDataLength.class)
    public void fromBech32_version0_invalidLength() {
        addressParser.parseAddress("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P");
    }

    @Test(expected = AddressFormatException.InvalidDataLength.class)
    public void fromBech32_tooShort() {
        addressParser.parseAddress("bc1rw5uspcuh");
    }

    @Test(expected = AddressFormatException.InvalidDataLength.class)
    public void fromBech32_tooLong() {
        addressParser.parseAddress("bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90");
    }

    @Test(expected = AddressFormatException.InvalidDataLength.class)
    public void fromBech32m_taprootTooShort() {
        // Taproot, valid bech32m encoding, checksum ok, padding ok, but no valid Segwit v1 program
        // (this program is 20 bytes long, but only 32 bytes program length are valid for Segwit v1/Taproot)
        String taprootAddressWith20BytesWitnessProgram = "bc1pqypqzqspqgqsyqgzqypqzqspqgqsyqgzzezy58";
        SegwitAddress.fromBech32(taprootAddressWith20BytesWitnessProgram, MAINNET);
    }

    @Test(expected = AddressFormatException.InvalidDataLength.class)
    public void fromBech32m_taprootTooLong() {
        // Taproot, valid bech32m encoding, checksum ok, padding ok, but no valid Segwit v1 program
        // (this program is 40 bytes long, but only 32 bytes program length are valid for Segwit v1/Taproot)
        String taprootAddressWith40BytesWitnessProgram = "bc1p6t0pcqrq3mvedn884lgj9s2cm52xp9vtnlc89cv5x77f5l725rrdjhqrld6m6rza67j62a";
        SegwitAddress.fromBech32(taprootAddressWith40BytesWitnessProgram, MAINNET);
    }

    @Test(expected = AddressFormatException.InvalidPrefix.class)
    public void fromBech32_invalidHrp() {
        addressParser.parseAddress("tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty");
    }

    @Test(expected = AddressFormatException.WrongNetwork.class)
    public void fromBech32_wrongNetwork() {
        SegwitAddress.fromBech32("bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj", TESTNET);
    }
}
