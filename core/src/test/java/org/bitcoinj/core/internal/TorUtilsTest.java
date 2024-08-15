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

package org.bitcoinj.core.internal;

import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;

public class TorUtilsTest {
    @Test
    public void roundtripOnionV2() {
        byte[] onionAddr = new byte[10];
        byte[] onionAddrCopy = TorUtils.decodeOnionUrl(TorUtils.encodeOnionUrlV2(onionAddr));
        assertArrayEquals(onionAddr, onionAddrCopy);
    }

    @Test
    public void roundtripOnionV3() {
        byte[] onionAddr = new byte[32];
        byte[] onionAddrCopy = TorUtils.decodeOnionUrl(TorUtils.encodeOnionUrlV3(onionAddr));
        assertArrayEquals(onionAddr, onionAddrCopy);
    }

    @Test(expected = IllegalArgumentException.class)
    public void encodeOnionUrlV2_badLength() {
        TorUtils.encodeOnionUrlV2(new byte[11]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void encodeOnionUrlV3_badLength() {
        TorUtils.encodeOnionUrlV2(new byte[33]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void decodeOnionUrl_badLength() {
        TorUtils.decodeOnionUrl("aaa.onion");
    }
}
