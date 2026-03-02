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

package org.bitcoinj.wallet;

import org.junit.Test;
import java.time.Instant;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class DeterministicSeedTest {

    @Test
    public void testToString() {
        long creationTime = 1000L;
        DeterministicSeed seed = new DeterministicSeed("correct horse battery staple", null, "", Instant.ofEpochSecond(creationTime));

        String s1 = seed.toString();
        assertTrue(s1.contains("DeterministicSeed"));
        assertTrue(s1.contains("unencrypted"));
        assertFalse("Security Fail: toString() leaked the mnemonic!", s1.contains("correct horse battery staple"));

        String s2 = seed.toString(true);
        assertTrue(s2.contains("correct horse battery staple"));
        assertTrue(s2.contains("mnemonicCode"));
    }
}
