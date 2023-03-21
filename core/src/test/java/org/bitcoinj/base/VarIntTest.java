/*
 * Copyright 2011 Google Inc.
 * Copyright 2018 Andreas Schildbach
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

package org.bitcoinj.base;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class VarIntTest {

    @Test
    public void testBytes() {
        VarInt a = VarInt.of(10); // with widening conversion
        assertEquals(1, a.getSizeInBytes());
        assertEquals(1, a.encode().length);
        assertEquals(10, VarInt.ofBytes(a.encode(), 0).intValue());
    }

    @Test
    public void testShorts() {
        VarInt a = VarInt.of(64000); // with widening conversion
        assertEquals(3, a.getSizeInBytes());
        assertEquals(3, a.encode().length);
        assertEquals(64000, VarInt.ofBytes(a.encode(), 0).intValue());
    }

    @Test
    public void testShortFFFF() {
        VarInt a = VarInt.of(0xFFFFL);
        assertEquals(3, a.getSizeInBytes());
        assertEquals(3, a.encode().length);
        assertEquals(0xFFFFL, VarInt.ofBytes(a.encode(), 0).intValue());
    }

    @Test
    public void testInts() {
        VarInt a = VarInt.of(0xAABBCCDDL);
        assertEquals(5, a.getSizeInBytes());
        assertEquals(5, a.encode().length);
        byte[] bytes = a.encode();
        assertEquals(0xAABBCCDDL, VarInt.ofBytes(bytes, 0).longValue());
    }

    @Test
    public void testIntFFFFFFFF() {
        VarInt a = VarInt.of(0xFFFFFFFFL);
        assertEquals(5, a.getSizeInBytes());
        assertEquals(5, a.encode().length);
        byte[] bytes = a.encode();
        assertEquals(0xFFFFFFFFL, VarInt.ofBytes(bytes, 0).longValue());
    }

    @Test
    public void testLong() {
        VarInt a = VarInt.of(0xCAFEBABEDEADBEEFL);
        assertEquals(9, a.getSizeInBytes());
        assertEquals(9, a.encode().length);
        byte[] bytes = a.encode();
        assertEquals(0xCAFEBABEDEADBEEFL, VarInt.ofBytes(bytes, 0).longValue());
    }

    @Test
    public void testSizeOfNegativeInt() {
        // shouldn't normally be passed, but at least stay consistent (bug regression test)
        assertEquals(VarInt.sizeOf(-1), VarInt.of(-1).encode().length);
    }
}
