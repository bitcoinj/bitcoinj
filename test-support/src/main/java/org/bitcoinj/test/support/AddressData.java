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

package org.bitcoinj.test.support;

import org.bitcoinj.base.BitcoinNetwork;

import static org.bitcoinj.base.BitcoinNetwork.MAINNET;
import static org.bitcoinj.base.BitcoinNetwork.TESTNET;

/**
 * AddressData wrapper class with valid and invalid address test vectors.
 */
public class AddressData {
    public static AddressData[] VALID_ADDRESSES = {
            // from BIP350 (includes the corrected BIP173 vectors):
            new AddressData("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", MAINNET,
                    "0014751e76e8199196d454941c45d1b3a323f1433bd6", 0),
            new AddressData("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", TESTNET,
                    "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262", 0),
            new AddressData("BC1SW50QGDZ25J", MAINNET, "6002751e", 16),
            new AddressData("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", MAINNET, "5210751e76e8199196d454941c45d1b3a323", 2),
            new AddressData("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", TESTNET,
                    "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", 0),
            new AddressData("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", TESTNET,
                    "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433", 1),
            new AddressData("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", MAINNET,
                    "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 1),
    };
    public static String[] INVALID_ADDRESSES = {
            // from BIP173:
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

            // from BIP350:
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty", // Invalid human-readable part
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", // Invalid checksum
            "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2", // Invalid witness version
            "bc1rw5uspcuh", // Invalid program length
            "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90", // Invalid program length
            "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", // Invalid program length for witness version 0 (per BIP141)
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7", // Mixed case
            "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", // zero padding of more than 4 bits
            "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv", // Non-zero padding in 8-to-5 conversion
            "bc1gmk9yu", // Empty data section
    };
    public final String address;
    public final BitcoinNetwork expectedNetwork;
    public final String expectedScriptPubKey;
    public final int expectedWitnessVersion;

    public AddressData(String address, BitcoinNetwork expectedNetwork, String expectedScriptPubKey,
                       int expectedWitnessVersion) {
        this.address = address;
        this.expectedNetwork = expectedNetwork;
        this.expectedScriptPubKey = expectedScriptPubKey;
        this.expectedWitnessVersion = expectedWitnessVersion;
    }

    @Override
    public String toString() {
        StringBuilder s = new StringBuilder(this.getClass().getSimpleName()).append('{');
        s.append("address=").append(address).append(',');
        s.append("expected=").append(expectedNetwork.id()).append(',').append(expectedScriptPubKey).append(',').append(expectedWitnessVersion);
        return s.append('}').toString();
    }
}
