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

package org.bitcoinj.crypto;

import org.bitcoinj.base.BitcoinNetwork;
import org.junit.Test;

import java.util.Collections;

import static org.junit.Assert.fail;

public class DeterministicKeyTest {
    @Test
    public void serialize_depthOverflow() {
        DeterministicKey masterPrivateKey = HDKeyDerivation.createMasterPrivateKey(new byte[16]);
        DeterministicHierarchy dh = new DeterministicHierarchy(masterPrivateKey);
        HDPath path = new HDPath(false, Collections.nCopies(255, ChildNumber.ZERO));
        DeterministicKey ehkey = dh.get(path, false, true);

        ehkey.serialize(BitcoinNetwork.MAINNET, false); // still fine at depth 255

        path = path.extend(ChildNumber.ZERO);
        ehkey = dh.get(path, false, true);
        try {
            ehkey.serialize(BitcoinNetwork.MAINNET, false); // throw at depth 256
            fail();
        } catch (IllegalArgumentException x) {
            // expected
        }
    }
}
