/*
 * Copyright by the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import static org.junit.Assert.assertEquals;
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class BaseUtilsTest {
    @Test
    public void base32Roundtrip() {
        byte[] data = new byte[128];
        new Random().nextBytes(data);

        String encoded = BaseUtils.base32Encode(data);
        byte[] decoded = BaseUtils.base32Decode(encoded);

        assertArrayEquals("Roundtrip decoding failed", data, decoded);
    }

    @Test
    public void base32Vectors() {
        checkEncoding("", "");
        checkEncoding("f", "my");
        checkEncoding("fo", "mzxq");
        checkEncoding("foo", "mzxw6");
        checkEncoding("foob", "mzxw6yq");
        checkEncoding("fooba", "mzxw6ytb");
        checkEncoding("foobar", "mzxw6ytboi");
    }

    private void checkEncoding(String input, String expectedOutput) {
        byte[] inputBytes = input.getBytes(StandardCharsets.UTF_8);
        assertEquals(expectedOutput, BaseUtils.base32Encode(inputBytes));
        assertArrayEquals(inputBytes, BaseUtils.base32Decode(expectedOutput));
    }
}
