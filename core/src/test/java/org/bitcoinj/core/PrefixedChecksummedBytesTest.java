/*
 * Copyright 2014 bitcoinj project
 * Copyright 2019 Tim Strasser
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

import nl.jqno.equalsverifier.EqualsVerifier;
import nl.jqno.equalsverifier.Warning;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.params.TestNet3Params;
import org.easymock.EasyMockRunner;
import org.easymock.Mock;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.bitcoinj.core.Utils.HEX;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;

@RunWith(EasyMockRunner.class)
public class PrefixedChecksummedBytesTest {

    @Mock
    NetworkParameters params;

    private static class PrefixedChecksummedBytesToTest extends PrefixedChecksummedBytes {
        public PrefixedChecksummedBytesToTest(NetworkParameters params, byte[] bytes) {
            super(params, bytes);
        }

        @Override
        public String toString() {
            return Base58.encodeChecked(params.getAddressHeader(), bytes);
        }
    }

    @Test
    public void equalsContract() {
        EqualsVerifier.forClass(PrefixedChecksummedBytes.class)
                .withPrefabValues(NetworkParameters.class, MainNetParams.get(), TestNet3Params.get())
                .suppress(Warning.NULL_FIELDS)
                .suppress(Warning.TRANSIENT_FIELDS)
                .usingGetClass()
                .verify();
    }

    @Test
    public void stringification() {
        // Test a testnet address.
        expect(params.getAddressHeader()).andReturn(111).andReturn(0);
        replay(params);

        PrefixedChecksummedBytes a = new PrefixedChecksummedBytesToTest(params, HEX.decode("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc"));
        assertEquals("n4eA2nbYqErp7H6jebchxAN59DmNpksexv", a.toString());

        PrefixedChecksummedBytes b = new PrefixedChecksummedBytesToTest(params, HEX.decode("4a22c3c4cbb31e4d03b15550636762bda0baf85a"));
        assertEquals("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL", b.toString());
    }

    @Test
    public void cloning() throws Exception {
        expect(params.getAddressHeader()).andReturn(111);
        replay(params);

        PrefixedChecksummedBytes a = new PrefixedChecksummedBytesToTest(params, HEX.decode("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc"));
        PrefixedChecksummedBytes b = a.clone();

        assertEquals(a, b);
        assertNotSame(a, b);
    }

    @Test
    public void comparisonCloneEqualTo() throws Exception {
        expect(params.getAddressHeader()).andReturn(111);
        expect(params.getId()).andReturn("org.bitcoin.test").times(2);
        replay(params);

        PrefixedChecksummedBytes a = new PrefixedChecksummedBytesToTest(params, HEX.decode("fda79a24e50ff70ff42f7d89585da5bd19d9e5cc"));
        PrefixedChecksummedBytes b = a.clone();

        assertNotSame(a, b);
        assertEquals(a, b);
    }
}
