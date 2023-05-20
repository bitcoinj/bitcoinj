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

package org.bitcoinj.base.internal;

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import nl.jqno.equalsverifier.EqualsVerifier;
import nl.jqno.equalsverifier.Warning;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

@RunWith(JUnitParamsRunner.class)
public class ByteArrayTest {

    @Test
    public void testImmutability() {
        byte[] bytes = new byte[]{0x00};
        ByteArray ba = new ByteArray(bytes);
        // Modify original array
        bytes[0] = (byte) 0xFF;

        // Verify ByteArray not modified (due to defensive copy)
        assertNotEquals(ba.bytes, bytes);
    }

    @Test
    public void equalsContract() {
        EqualsVerifier.forClass(ByteArray.class)
                .suppress(Warning.NULL_FIELDS)
                .suppress(Warning.TRANSIENT_FIELDS)
                .usingGetClass()
                .verify();
    }

    @Test
    @Parameters(method = "bytesToHexStringVectors")
    public void formatHexValid(byte[] bytes, String expectedHexString) {
        ByteArray ba = new ByteArray(bytes);
        assertEquals("incorrect hex formatted string", expectedHexString, ba.formatHex());
    }

    // Two-way test vectors (can be used to validate mapping in both directions)
    private Object[] bytesToHexStringVectors() {
        return new Object[]{
                new Object[]{ new byte[] {}, ""},
                new Object[]{ new byte[] {0x00}, "00"},
                new Object[]{ new byte[] {(byte) 0xff}, "ff"},
                new Object[]{ new byte[] {(byte) 0xab, (byte) 0xcd, (byte) 0xef}, "abcdef"}
        };
    }
}
