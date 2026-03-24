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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class InventoryItemTest {

    private static final Sha256Hash HASH_1 = Sha256Hash.wrap("0000000000000000000000000000000000000000000000000000000000000001");
    private static final Sha256Hash HASH_2 = Sha256Hash.wrap("0000000000000000000000000000000000000000000000000000000000000002");

    @Test
    public void constructWithTypeAndHash() {
        InventoryItem item = new InventoryItem(InventoryItem.Type.TRANSACTION, HASH_1);
        assertEquals(InventoryItem.Type.TRANSACTION, item.type);
        assertEquals(HASH_1, item.hash);
    }

    @Test
    public void messageLength() {
        assertEquals(36, InventoryItem.MESSAGE_LENGTH);
    }

    @Test
    public void typeOfCode_transaction() {
        assertEquals(InventoryItem.Type.TRANSACTION, InventoryItem.Type.ofCode(0x1));
    }

    @Test
    public void typeOfCode_block() {
        assertEquals(InventoryItem.Type.BLOCK, InventoryItem.Type.ofCode(0x2));
    }

    @Test
    public void typeOfCode_filteredBlock() {
        assertEquals(InventoryItem.Type.FILTERED_BLOCK, InventoryItem.Type.ofCode(0x3));
    }

    @Test
    public void typeOfCode_error() {
        assertEquals(InventoryItem.Type.ERROR, InventoryItem.Type.ofCode(0x0));
    }

    @Test
    public void typeOfCode_witnessTransaction() {
        assertEquals(InventoryItem.Type.WITNESS_TRANSACTION, InventoryItem.Type.ofCode(0x40000001));
    }

    @Test
    public void typeOfCode_witnessBlock() {
        assertEquals(InventoryItem.Type.WITNESS_BLOCK, InventoryItem.Type.ofCode(0x40000002));
    }

    @Test
    public void typeOfCode_witnessFilteredBlock() {
        assertEquals(InventoryItem.Type.WITNESS_FILTERED_BLOCK, InventoryItem.Type.ofCode(0x40000003));
    }

    @Test
    public void typeOfCode_unknownReturnsNull() {
        assertNull(InventoryItem.Type.ofCode(0x99));
    }

    @Test
    public void typeOfCode_negativeReturnsNull() {
        assertNull(InventoryItem.Type.ofCode(-1));
    }

    @Test
    public void typeCodes() {
        assertEquals(0x0, InventoryItem.Type.ERROR.code);
        assertEquals(0x1, InventoryItem.Type.TRANSACTION.code);
        assertEquals(0x2, InventoryItem.Type.BLOCK.code);
        assertEquals(0x3, InventoryItem.Type.FILTERED_BLOCK.code);
        assertEquals(0x40000001, InventoryItem.Type.WITNESS_TRANSACTION.code);
        assertEquals(0x40000002, InventoryItem.Type.WITNESS_BLOCK.code);
        assertEquals(0x40000003, InventoryItem.Type.WITNESS_FILTERED_BLOCK.code);
    }

    @Test
    public void equalsWithSameTypeAndHash() {
        InventoryItem item1 = new InventoryItem(InventoryItem.Type.TRANSACTION, HASH_1);
        InventoryItem item2 = new InventoryItem(InventoryItem.Type.TRANSACTION, HASH_1);
        assertEquals(item1, item2);
        assertEquals(item1.hashCode(), item2.hashCode());
    }

    @Test
    public void equalsWithDifferentHash() {
        InventoryItem item1 = new InventoryItem(InventoryItem.Type.TRANSACTION, HASH_1);
        InventoryItem item2 = new InventoryItem(InventoryItem.Type.TRANSACTION, HASH_2);
        assertNotEquals(item1, item2);
    }

    @Test
    public void equalsWithDifferentType() {
        InventoryItem item1 = new InventoryItem(InventoryItem.Type.TRANSACTION, HASH_1);
        InventoryItem item2 = new InventoryItem(InventoryItem.Type.BLOCK, HASH_1);
        assertNotEquals(item1, item2);
    }

    @Test
    public void equalsWithSelf() {
        InventoryItem item = new InventoryItem(InventoryItem.Type.TRANSACTION, HASH_1);
        assertEquals(item, item);
    }

    @Test
    public void equalsWithNull() {
        InventoryItem item = new InventoryItem(InventoryItem.Type.TRANSACTION, HASH_1);
        assertNotEquals(null, item);
    }

    @Test
    public void equalsWithDifferentClass() {
        InventoryItem item = new InventoryItem(InventoryItem.Type.TRANSACTION, HASH_1);
        assertFalse(item.equals("not an inventory item"));
    }

    @Test
    public void toStringContainsTypeAndHash() {
        InventoryItem item = new InventoryItem(InventoryItem.Type.BLOCK, HASH_1);
        String str = item.toString();
        assertTrue(str.contains("BLOCK"));
        assertTrue(str.contains(HASH_1.toString()));
    }

    @Test
    public void hashCodeConsistency() {
        InventoryItem item = new InventoryItem(InventoryItem.Type.TRANSACTION, HASH_1);
        assertEquals(item.hashCode(), item.hashCode());
    }

    @Test
    public void allTypeValuesResolvable() {
        for (InventoryItem.Type type : InventoryItem.Type.values()) {
            InventoryItem.Type resolved = InventoryItem.Type.ofCode(type.code);
            assertNotNull("Type " + type + " should be resolvable by its code", resolved);
            assertEquals(type, resolved);
        }
    }

    @Test
    public void typeEnumHasExpectedCount() {
        // ERROR, TRANSACTION, BLOCK, FILTERED_BLOCK, WITNESS_TRANSACTION, WITNESS_BLOCK, WITNESS_FILTERED_BLOCK
        assertEquals(7, InventoryItem.Type.values().length);
    }
}
