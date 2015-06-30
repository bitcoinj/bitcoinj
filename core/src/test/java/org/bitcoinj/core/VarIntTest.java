/**
 * Copyright 2011 Google Inc.
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

import junit.framework.TestCase;

import org.junit.Test;

public class VarIntTest extends TestCase {

    @Test
    public void testBytes() throws Exception {
        VarInt a = new VarInt(10); // with widening conversion
        assertEquals(1, a.getSizeInBytes());
        assertEquals(1, a.encode().length);
        assertEquals(10, new VarInt(a.encode(), 0).value);
    }

    @Test
    public void testShorts() throws Exception {
        VarInt a = new VarInt(64000); // with widening conversion
        assertEquals(3, a.getSizeInBytes());
        assertEquals(3, a.encode().length);
        assertEquals(64000, new VarInt(a.encode(), 0).value);
    }

    @Test
    public void testShortFFFF() throws Exception {
        VarInt a = new VarInt(0xFFFFL);
        assertEquals(3, a.getSizeInBytes());
        assertEquals(3, a.encode().length);
        assertEquals(0xFFFFL, new VarInt(a.encode(), 0).value);
    }

    @Test
    public void testInts() throws Exception {
        VarInt a = new VarInt(0xAABBCCDDL);
        assertEquals(5, a.getSizeInBytes());
        assertEquals(5, a.encode().length);
        byte[] bytes = a.encode();
        assertEquals(0xAABBCCDDL, 0xFFFFFFFFL & new VarInt(bytes, 0).value);
    }

    @Test
    public void testIntFFFFFFFF() throws Exception {
        VarInt a = new VarInt(0xFFFFFFFFL);
        assertEquals(5, a.getSizeInBytes());
        assertEquals(5, a.encode().length);
        byte[] bytes = a.encode();
        assertEquals(0xFFFFFFFFL, 0xFFFFFFFFL & new VarInt(bytes, 0).value);
    }

    @Test
    public void testLong() throws Exception {
        VarInt a = new VarInt(0xCAFEBABEDEADBEEFL);
        assertEquals(9, a.getSizeInBytes());
        assertEquals(9, a.encode().length);
        byte[] bytes = a.encode();
        assertEquals(0xCAFEBABEDEADBEEFL, new VarInt(bytes, 0).value);
    }

    @Test
    public void testSizeOfNegativeInt() throws Exception {
        // shouldn't normally be passed, but at least stay consistent (bug regression test)
        assertEquals(VarInt.sizeOf(-1), new VarInt(-1).encode().length);
    }
}
