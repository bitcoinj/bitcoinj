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

package org.bitcoinj.core;

import org.bitcoinj.base.Sha256Hash;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class BlockLocatorTest {

    private static final Sha256Hash HASH_1 = Sha256Hash.wrap("0000000000000000000000000000000000000000000000000000000000000001");
    private static final Sha256Hash HASH_2 = Sha256Hash.wrap("0000000000000000000000000000000000000000000000000000000000000002");
    private static final Sha256Hash HASH_3 = Sha256Hash.wrap("0000000000000000000000000000000000000000000000000000000000000003");

    @Test
    public void constructWithList() {
        List<Sha256Hash> hashes = Arrays.asList(HASH_1, HASH_2, HASH_3);
        BlockLocator locator = new BlockLocator(hashes);

        assertEquals(3, locator.size());
        assertEquals(HASH_1, locator.get(0));
        assertEquals(HASH_2, locator.get(1));
        assertEquals(HASH_3, locator.get(2));
    }

    @Test
    public void constructEmpty() {
        @SuppressWarnings("deprecation")
        BlockLocator locator = new BlockLocator();

        assertEquals(0, locator.size());
        assertTrue(locator.getHashes().isEmpty());
    }

    @Test
    public void constructWithEmptyList() {
        BlockLocator locator = new BlockLocator(Collections.emptyList());

        assertEquals(0, locator.size());
        assertTrue(locator.getHashes().isEmpty());
    }

    @Test
    public void constructWithSingleHash() {
        BlockLocator locator = new BlockLocator(Collections.singletonList(HASH_1));

        assertEquals(1, locator.size());
        assertEquals(HASH_1, locator.get(0));
    }

    @Test(expected = UnsupportedOperationException.class)
    public void hashesAreUnmodifiable() {
        BlockLocator locator = new BlockLocator(Arrays.asList(HASH_1, HASH_2));
        locator.getHashes().add(HASH_3);
    }

    @Test
    public void originalListModificationDoesNotAffectLocator() {
        List<Sha256Hash> hashes = new ArrayList<>(Arrays.asList(HASH_1, HASH_2));
        BlockLocator locator = new BlockLocator(hashes);
        hashes.add(HASH_3);

        assertEquals(2, locator.size());
    }

    @Test
    @SuppressWarnings("deprecation")
    public void deprecatedAddCreatesNewInstance() {
        BlockLocator locator1 = new BlockLocator();
        BlockLocator locator2 = locator1.add(HASH_1);
        BlockLocator locator3 = locator2.add(HASH_2);

        assertEquals(0, locator1.size());
        assertEquals(1, locator2.size());
        assertEquals(2, locator3.size());
        assertEquals(HASH_1, locator3.get(0));
        assertEquals(HASH_2, locator3.get(1));
    }

    @Test(expected = IndexOutOfBoundsException.class)
    public void getOutOfBounds() {
        BlockLocator locator = new BlockLocator(Collections.singletonList(HASH_1));
        locator.get(1);
    }

    @Test
    public void equalsAndHashCode() {
        BlockLocator locator1 = new BlockLocator(Arrays.asList(HASH_1, HASH_2));
        BlockLocator locator2 = new BlockLocator(Arrays.asList(HASH_1, HASH_2));
        BlockLocator locator3 = new BlockLocator(Arrays.asList(HASH_1, HASH_3));

        assertEquals(locator1, locator2);
        assertEquals(locator1.hashCode(), locator2.hashCode());
        assertNotEquals(locator1, locator3);
    }

    @Test
    public void equalsWithSelf() {
        BlockLocator locator = new BlockLocator(Arrays.asList(HASH_1, HASH_2));
        assertEquals(locator, locator);
    }

    @Test
    public void equalsWithNull() {
        BlockLocator locator = new BlockLocator(Arrays.asList(HASH_1, HASH_2));
        assertNotEquals(null, locator);
    }

    @Test
    public void equalsWithDifferentType() {
        BlockLocator locator = new BlockLocator(Arrays.asList(HASH_1, HASH_2));
        assertFalse(locator.equals("not a block locator"));
    }

    @Test
    public void equalsEmptyLocators() {
        BlockLocator locator1 = new BlockLocator(Collections.emptyList());
        @SuppressWarnings("deprecation")
        BlockLocator locator2 = new BlockLocator();
        assertEquals(locator1, locator2);
    }

    @Test
    public void toStringContainsSize() {
        BlockLocator locator = new BlockLocator(Arrays.asList(HASH_1, HASH_2));
        String str = locator.toString();
        assertTrue(str.contains("2"));
    }

    @Test
    public void toStringEmpty() {
        BlockLocator locator = new BlockLocator(Collections.emptyList());
        String str = locator.toString();
        assertTrue(str.contains("0"));
    }

    @Test
    public void hashCodeConsistency() {
        BlockLocator locator = new BlockLocator(Arrays.asList(HASH_1, HASH_2, HASH_3));
        int hash1 = locator.hashCode();
        int hash2 = locator.hashCode();
        assertEquals(hash1, hash2);
    }

    @Test
    public void equalsWithDifferentOrder() {
        BlockLocator locator1 = new BlockLocator(Arrays.asList(HASH_1, HASH_2));
        BlockLocator locator2 = new BlockLocator(Arrays.asList(HASH_2, HASH_1));
        assertNotEquals(locator1, locator2);
    }

    @Test
    public void equalsWithDifferentSize() {
        BlockLocator locator1 = new BlockLocator(Arrays.asList(HASH_1, HASH_2));
        BlockLocator locator2 = new BlockLocator(Collections.singletonList(HASH_1));
        assertNotEquals(locator1, locator2);
    }
}
