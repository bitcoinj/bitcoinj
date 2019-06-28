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

import org.junit.Assert;
import org.junit.Test;

import java.util.Collections;

/**
 * @author Michael Sean Gilligan
 */
public class HDPathTest {
    @Test
    public void testPrimaryConstructor() throws Exception {
        HDPath path = new HDPath(true, Collections.<ChildNumber>emptyList());
        Assert.assertTrue("Has private key returns false incorrectly", path.hasPrivateKey);
        Assert.assertEquals("Path not empty", path.size(), 0);
    }

    @Test
    public void testExtendVarargs() throws Exception {
        HDPath basePath = new HDPath(true, Collections.<ChildNumber>emptyList());
        // Make sure we can do a depth of 5 as per BIP44, etc.
        // m / 44' / coinType' / accountIndex' / change / addressIndex
        HDPath path1 = basePath.extend(ChildNumber.ZERO_HARDENED);
        HDPath path2 = basePath.extend(ChildNumber.ZERO_HARDENED, ChildNumber.ONE_HARDENED);
        HDPath path3 = basePath.extend(ChildNumber.ZERO_HARDENED, ChildNumber.ONE_HARDENED, ChildNumber.ZERO_HARDENED);
        HDPath path4 = basePath.extend(ChildNumber.ZERO_HARDENED, ChildNumber.ONE_HARDENED, ChildNumber.ZERO_HARDENED, ChildNumber.ONE);
        HDPath path5 = basePath.extend(ChildNumber.ZERO_HARDENED, ChildNumber.ONE_HARDENED, ChildNumber.ZERO_HARDENED, ChildNumber.ONE, ChildNumber.ZERO);

        Assert.assertEquals("m/0H",  path1.toString());
        Assert.assertEquals("m/0H/1H",  path2.toString());
        Assert.assertEquals("m/0H/1H/0H",  path3.toString());
        Assert.assertEquals("m/0H/1H/0H/1",  path4.toString());
        Assert.assertEquals("m/0H/1H/0H/1/0",  path5.toString());
    }
}
