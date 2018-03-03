/*
 * Copyright 2018 Coinomi Ltd
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.util.Locale;

import org.junit.Test;

public class Bech32Test {
    @Test
    public void valid() {
        for (String valid : VALID) {
            Bech32.Bech32Data bechData = Bech32.decode(valid);
            String recode = Bech32.encode(bechData);
            assertEquals(String.format("Failed to roundtrip '%s' -> '%s'", valid, recode),
                    valid.toLowerCase(Locale.ROOT), recode.toLowerCase(Locale.ROOT));
            // Test encoding with an uppercase HRP
            recode = Bech32.encode(bechData.hrp.toUpperCase(Locale.ROOT), bechData.data);
            assertEquals(String.format("Failed to roundtrip '%s' -> '%s'", valid, recode),
                    valid.toLowerCase(Locale.ROOT), recode.toLowerCase(Locale.ROOT));
        }
    }

    private static final String[] VALID = {
            "A12UEL5L",
            "a12uel5l",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
            "?1ezyfcl",
    };

    @Test
    public void invalid() {
        for (String invalid : INVALID) {
            try {
                Bech32.decode(invalid);
                fail(String.format("Parsed an invalid code: '%s'", invalid));
            } catch (AddressFormatException x) {
                /* expected */
            }
        }
    }

    private static final String[] INVALID = {
            " 1nwldj5", // HRP character out of range
            new String(new char[] { 0x7f }) + "1axkwrx", // HRP character out of range
            new String(new char[] { 0x80 }) + "1eym55h", // HRP character out of range
            "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx", // overall max length exceeded
            "pzry9x0s0muk", // No separator character
            "1pzry9x0s0muk", // Empty HRP
            "x1b4n0q5v", // Invalid data character
            "li1dgmt3", // Too short checksum
            "de1lg7wt" + new String(new char[] { 0xff }), // Invalid character in checksum
            "A1G7SGD8", // checksum calculated with uppercase form of HRP
            "10a06t8", // empty HRP
            "1qzzfhee", // empty HRP
    };

    @Test(expected = AddressFormatException.InvalidCharacter.class)
    public void decode_invalidCharacter_notInAlphabet() {
        Bech32.decode("A12OUEL5X");
    }

    @Test(expected = AddressFormatException.InvalidCharacter.class)
    public void decode_invalidCharacter_upperLowerMix() {
        Bech32.decode("A12UeL5X");
    }

    @Test(expected = AddressFormatException.InvalidChecksum.class)
    public void decode_invalidNetwork() {
        Bech32.decode("A12UEL5X");
    }

    @Test(expected = AddressFormatException.InvalidPrefix.class)
    public void decode_invalidHrp() {
        Bech32.decode("1pzry9x0s0muk");
    }
}
