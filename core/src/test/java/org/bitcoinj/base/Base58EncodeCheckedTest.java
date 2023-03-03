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

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;

import org.bitcoinj.base.internal.ByteUtils;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class Base58EncodeCheckedTest {

    private int version;
    private byte[] input;
    private String expected;

    @Parameters
    public static Collection<Object[]> parameters() {
        return Arrays.asList(new Object[][]{
                {111, new byte[LegacyAddress.LENGTH], "mfWxJ45yp2SFn7UciZyNpvDKrzbhyfKrY8"},
                {128, new byte[32], "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU"},
                {111, ByteUtils.parseHex("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc"), "n4eA2nbYqErp7H6jebchxAN59DmNpksexv"},
                {0, ByteUtils.parseHex("4a22c3c4cbb31e4d03b15550636762bda0baf85a"), "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL"}
        });
    }

    public Base58EncodeCheckedTest(int version, byte[] input, String expected) {
        this.version = version;
        this.input = input;
        this.expected = expected;
    }

    @Test
    public void testEncode() {
        assertEquals(expected, Base58.encodeChecked(version, input));
    }
}
