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

import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

/**
 * @author Michael Sean Gilligan
 */
@RunWith(JUnitParamsRunner.class)
public class HDPathTest {
    @Test
    public void testPrimaryConstructor() {
        HDPath.HDFullPath path = HDPath.m();
        assertTrue("Has private key returns false incorrectly", path.hasPrivateKey());
        assertEquals("Path not empty", 0, path.size());
    }

    @Test
    public void testExtendVarargs() {
        HDPath.HDFullPath  basePath = HDPath.m();

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

    private PathVector[] toStringTestVectors() {
        return new PathVector[] {
                new PathVector (
                        "M/44H/0H/0H/1/1",
                        HDPath.M(new ChildNumber(44, true), new ChildNumber(0, true), new ChildNumber(0, true),
                                new ChildNumber(1, false), new ChildNumber(1, false))
                ),
                new PathVector (
                        "M/7H/3/3/1H",
                        HDPath.M(new ChildNumber(7, true), new ChildNumber(3, false), new ChildNumber(3, false),
                                new ChildNumber(1, true))
                ),
                new PathVector (
                        "M/1H/2H/3H",
                        HDPath.M(new ChildNumber(1, true), new ChildNumber(2, true), new ChildNumber(3, true))
                ),
                new PathVector (
                        "M/1/2/3",
                        HDPath.M(new ChildNumber(1, false), new ChildNumber(2, false), new ChildNumber(3, false))
                ),
                new PathVector (
                        "/44H/0H/0H/1/1",
                        HDPath.partial(new ChildNumber(44, true), new ChildNumber(0, true), new ChildNumber(0, true),
                                new ChildNumber(1, false), new ChildNumber(1, false))
                ),
                new PathVector (
                        "/7H/3/3/1H",
                        HDPath.partial(new ChildNumber(7, true), new ChildNumber(3, false), new ChildNumber(3, false),
                                new ChildNumber(1, true))
                ),
                new PathVector (
                        "/1H/2H/3H",
                        HDPath.partial(new ChildNumber(1, true), new ChildNumber(2, true), new ChildNumber(3, true))
                ),
                new PathVector (
                        "/1/2/3",
                        HDPath.partial(new ChildNumber(1, false), new ChildNumber(2, false), new ChildNumber(3, false))
                )
        };
    }

    @Test
    @Parameters(method = "toStringTestVectors")
    public void testToString(PathVector tv) {
        String generatedStrPath = tv.path.toString();
        assertEquals(tv.pathString, generatedStrPath);
    }

    private PathVector[] parseTestVectors() {
        return new PathVector[] {
            new PathVector (
                "M / 44H / 0H / 0H / 1 / 1",
                HDPath.M(new ChildNumber(44, true), new ChildNumber(0, true), new ChildNumber(0, true),
                    new ChildNumber(1, false), new ChildNumber(1, false))
            ),

            new PathVector (
                "M/7H/3/3/1H/",
                HDPath.M(new ChildNumber(7, true), new ChildNumber(3, false), new ChildNumber(3, false),
                    new ChildNumber(1, true))
            ),

            new PathVector (
                "m/7H/3/3/1H/",
                HDPath.m(new ChildNumber(7, true), new ChildNumber(3, false), new ChildNumber(3, false),
                    new ChildNumber(1, true))
            ),

            new PathVector (
                "1 H / 2 H / 3 H /",
                HDPath.partial(new ChildNumber(1, true), new ChildNumber(2, true), new ChildNumber(3, true))
            ),

            new PathVector (
                "1 / 2 / 3 /",
                HDPath.partial(new ChildNumber(1, false), new ChildNumber(2, false), new ChildNumber(3, false))
            )
        };
    }

    @Test
    @Parameters(method = "toStringTestVectors, parseTestVectors")
    public void testParsePath(PathVector tv) {
        HDPath.HDFullPath path = HDPath.parsePath(tv.pathString);
        assertEquals(tv.path, path);
    }

    @Test
    @Parameters(method = "toStringTestVectors, parseTestVectors")
    public void testAsPartial(PathVector tv) {
        HDPath.HDPartialPath partialPath = tv.path.asPartial();
        assertEquals(tv.path.childNumbers, partialPath.childNumbers);
    }

    @Test
    @Ignore("Ignored until we have a correct implementation of equals that compares the prefix")
    public void equals_not_M_m() {
        assertNotEquals(HDPath.M(), HDPath.m());
    }

    // This should be a record
    public static class PathVector {
        final String pathString;
        final HDPath path;

        private PathVector(String pathString, HDPath path) {
            this.pathString = pathString;
            this.path = path;
        }
    }
}
