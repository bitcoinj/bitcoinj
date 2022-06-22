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

package org.bitcoinj.core;

import org.bitcoinj.base.Base58;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;

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
                {128, new byte[32], "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAbuatmU"}
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
