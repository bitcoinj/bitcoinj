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

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Michael Sean Gilligan
 */
public class HDPathTest {
    @Test
    public void testPrimaryConstructor() {
        HDPath path = new HDPath(true, Collections.emptyList());
        assertTrue("Has private key returns false incorrectly", path.hasPrivateKey);
        assertEquals("Path not empty", path.size(), 0);
    }

    @Test
    public void testExtendVarargs() {
        HDPath basePath = new HDPath(true, Collections.emptyList());

        assertTrue(basePath.hasPrivateKey());
        assertEquals("m",  basePath.toString());

        // Make sure we can do a depth of 5 as per BIP44, etc.
        // m / 44' / coinType' / accountIndex' / change / addressIndex
        HDPath path1 = basePath.extend(ChildNumber.ZERO_HARDENED);
        HDPath path2 = basePath.extend(ChildNumber.ZERO_HARDENED, ChildNumber.ONE_HARDENED);
        HDPath path3 = basePath.extend(ChildNumber.ZERO_HARDENED, ChildNumber.ONE_HARDENED, ChildNumber.ZERO_HARDENED);
        HDPath path4 = basePath.extend(ChildNumber.ZERO_HARDENED, ChildNumber.ONE_HARDENED, ChildNumber.ZERO_HARDENED, ChildNumber.ONE);
        HDPath path5 = basePath.extend(ChildNumber.ZERO_HARDENED, ChildNumber.ONE_HARDENED, ChildNumber.ZERO_HARDENED, ChildNumber.ONE, ChildNumber.ZERO);

        assertEquals("m/0H",  path1.toString());
        assertEquals("m/0H/1H",  path2.toString());
        assertEquals("m/0H/1H/0H",  path3.toString());
        assertEquals("m/0H/1H/0H/1",  path4.toString());
        assertEquals("m/0H/1H/0H/1/0",  path5.toString());
    }

    @Test
    public void testParent() {
        HDPath path1 = HDPath.parsePath("m/0H/1H");

        assertEquals(HDPath.parsePath("m/0H"), path1.parent());

        HDPath path2 = HDPath.parsePath("m/0H");

        assertEquals(HDPath.parsePath(""), path2.parent());

        HDPath path3 = HDPath.parsePath("");

        assertEquals(HDPath.parsePath(""), path3.parent());
    }

    @Test
    public void testAncestors() {
        HDPath path = HDPath.parsePath("m/0H/1H/0H/1/0");

        List<HDPath> ancestors = path.ancestors();

        assertEquals(4, ancestors.size());
        assertEquals(HDPath.parsePath("m/0H"),              ancestors.get(0));
        assertEquals(HDPath.parsePath("m/0H/1H"),           ancestors.get(1));
        assertEquals(HDPath.parsePath("m/0H/1H/0H"),        ancestors.get(2));
        assertEquals(HDPath.parsePath("m/0H/1H/0H/1"),      ancestors.get(3));


        List<HDPath> ancestorsWithSelf = path.ancestors(true);

        assertEquals(5, ancestorsWithSelf.size());
        assertEquals(HDPath.parsePath("m/0H"),              ancestorsWithSelf.get(0));
        assertEquals(HDPath.parsePath("m/0H/1H"),           ancestorsWithSelf.get(1));
        assertEquals(HDPath.parsePath("m/0H/1H/0H"),        ancestorsWithSelf.get(2));
        assertEquals(HDPath.parsePath("m/0H/1H/0H/1"),      ancestorsWithSelf.get(3));
        assertEquals(HDPath.parsePath("m/0H/1H/0H/1/0"),    ancestorsWithSelf.get(4));

        HDPath rootPath = HDPath.parsePath("m/0H");

        List<HDPath> empty = rootPath.ancestors();

        assertEquals(0, empty.size());

        List<HDPath> self = rootPath.ancestors(true);

        assertEquals(1, self.size());
        assertEquals(rootPath, self.get(0));


        HDPath emptyPath = HDPath.m();

        List<HDPath> empty2 = emptyPath.ancestors();

        assertEquals(0, empty2.size());

        List<HDPath> empty3 = emptyPath.ancestors(true);

        assertEquals(0, empty3.size());
    }

    @Test
    public void testFormatPath() {
        Object[] tv = {
                "M/44H/0H/0H/1/1",
                HDPath.M(new ChildNumber(44, true), new ChildNumber(0, true), new ChildNumber(0, true),
                        new ChildNumber(1, false), new ChildNumber(1, false)),

                "M/7H/3/3/1H",
                HDPath.M(new ChildNumber(7, true), new ChildNumber(3, false), new ChildNumber(3, false),
                        new ChildNumber(1, true)),

                "M/1H/2H/3H",
                HDPath.M(new ChildNumber(1, true), new ChildNumber(2, true), new ChildNumber(3, true)),

                "M/1/2/3",
                HDPath.M(new ChildNumber(1, false), new ChildNumber(2, false), new ChildNumber(3, false))
        };

        for (int i = 0; i < tv.length; i += 2) {
            String expectedStrPath = (String) tv[i];
            HDPath path = (HDPath) tv[i + 1];

            String generatedStrPath = path.toString();

            assertEquals(generatedStrPath, expectedStrPath);
        }
    }

    @Test
    public void testParsePath() {
        Object[] tv = {
                "M / 44H / 0H / 0H / 1 / 1",
                HDPath.M(new ChildNumber(44, true), new ChildNumber(0, true), new ChildNumber(0, true),
                        new ChildNumber(1, false), new ChildNumber(1, false)),
                false,

                "M/7H/3/3/1H/",
                HDPath.M(new ChildNumber(7, true), new ChildNumber(3, false), new ChildNumber(3, false),
                        new ChildNumber(1, true)),
                false,

                "m/7H/3/3/1H/",
                HDPath.m(new ChildNumber(7, true), new ChildNumber(3, false), new ChildNumber(3, false),
                        new ChildNumber(1, true)),
                true,

                "1 H / 2 H / 3 H /",
                Arrays.asList(new ChildNumber(1, true), new ChildNumber(2, true), new ChildNumber(3, true)),
                false,

                "1 / 2 / 3 /",
                Arrays.asList(new ChildNumber(1, false), new ChildNumber(2, false), new ChildNumber(3, false)),
                false
        };

        for (int i = 0; i < tv.length; i += 3) {
            String strPath = (String) tv[i];
            List<ChildNumber> expectedPath = (List<ChildNumber>) tv[i + 1];
            boolean expectedHasPrivateKey = (Boolean) tv[i + 2];

            HDPath path = HDPath.parsePath(strPath);
            assertEquals(path, expectedPath);
            assertEquals(path.hasPrivateKey, expectedHasPrivateKey);
        }
    }
}
