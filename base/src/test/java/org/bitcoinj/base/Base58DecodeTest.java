/*
 * Copyright 2011 Google Inc.
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

package org.bitcoinj.base;

import org.bitcoinj.base.exceptions.AddressFormatException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class Base58DecodeTest {

    private String input;
    private byte[] expected;

    public Base58DecodeTest(String input, byte[] expected) {
        this.input = input;
        this.expected = expected;
    }

    @Parameters
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                {"JxF12TrwUP45BMd", "Hello World".getBytes()},
                {"1", new byte[1]},
                {"1111", new byte[4]},
                {"11111111111111111111111111111111", new byte[32]}
        });
    }

    @Test
    public void testDecode() {
        byte[] actualBytes = Base58.decode(input);
        assertArrayEquals(input,  actualBytes, expected);
    }

    @Test
    public void testDecode_emptyString() {
        assertEquals(0, Base58.decode("").length);
    }

    @Test(expected = AddressFormatException.class)
    public void testDecode_invalidBase58() {
        Base58.decode("This isn't valid base58");
    }

    @Test
    public void testDecode_alphabetCharacters() {
        // Each character of the base58 alphabet decodes to its 1-byte index. The first
        // character ('1') is the encoded zero, so it decodes to a single zero byte.
        char[] alphabet = Base58.ALPHABET;
        for (int i = 0; i < alphabet.length; i++) {
            byte[] decoded = Base58.decode(String.valueOf(alphabet[i]));
            byte[] expected = i == 0 ? new byte[1] : new byte[]{(byte) i};
            assertArrayEquals("char=" + alphabet[i], expected, decoded);
        }
    }

    @Test
    public void testDecode_nonAscii() {
        // Characters outside the ASCII range (c >= 128), including supplementary code points
        // emitted as UTF-16 surrogate pairs, must be rejected with InvalidCharacter.
        String[] inputs = {"é", "中", "abc😀def"};
        for (String input : inputs) {
            try {
                Base58.decode(input);
                throw new AssertionError("expected AddressFormatException for input: " + input);
            } catch (AddressFormatException.InvalidCharacter expected) {
                // ok
            }
        }
    }
}
