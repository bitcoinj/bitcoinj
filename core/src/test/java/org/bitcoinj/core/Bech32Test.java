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
    public void validChecksum() {
        for (String valid : VALID_CHECKSUMS) {
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

    @Test
    public void invalidChecksum() {
        for (String invalid : INVALID_CHECKSUMS) {
            try {
                Bech32.decode(invalid);
                fail(String.format("Parsed an invalid code: '%s'", invalid));
            } catch (AddressFormatException x) {
                /* expected */
            }
        }
    }

    // test vectors

    private static String[] VALID_CHECKSUMS = {
            "A12UEL5L",
            "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
            "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
            "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
            "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w"
    };

    private static String[] INVALID_CHECKSUMS = {
            " 1nwldj5",
            new String(new char[] { 0x7f }) + "1axkwrx",
            "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
            "pzry9x0s0muk",
            "1pzry9x0s0muk",
            "x1b4n0q5v",
            "li1dgmt3",
            "de1lg7wt" + new String(new char[] { 0xff }),
    };
}
