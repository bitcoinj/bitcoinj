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
import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.ByteUtils;

import java.nio.BufferOverflowException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.bitcoinj.base.internal.Preconditions.check;

/**
 * Mix-in interface for classes with list-based payload, i.e., InventoryMessage and GetDataMessage.
 */
interface ListMessage extends Message {

    List<InventoryItem> items();

    int MAX_INVENTORY_ITEMS = 50000;

    static List<InventoryItem> readItems(ByteBuffer payload) throws BufferUnderflowException,
            ProtocolException {
        VarInt arrayLenVarInt = VarInt.read(payload);
        check(arrayLenVarInt.fitsInt(), BufferUnderflowException::new);
        int arrayLen = arrayLenVarInt.intValue();
        if (arrayLen > MAX_INVENTORY_ITEMS)
            throw new ProtocolException("Too many items in INV message: " + arrayLen);

        // An inv is vector<CInv> where CInv is int+hash. The int is either 1 or 2 for tx or block.
        List<InventoryItem> items = new ArrayList<>(arrayLen);
        for (int i = 0; i < arrayLen; i++) {
            if (payload.remaining() < InventoryItem.MESSAGE_LENGTH) {
                throw new ProtocolException("Ran off the end of the INV");
            }
            int typeCode = (int) ByteUtils.readUint32(payload);
            InventoryItem.Type type = InventoryItem.Type.ofCode(typeCode);
            if (type == null)
                throw new ProtocolException("Unknown CInv type: " + typeCode);
            InventoryItem item = new InventoryItem(type, Sha256Hash.read(payload));
            items.add(item);
        }
        return items;
    }

    default List<InventoryItem> getItems() {
        return Collections.unmodifiableList(items());
    }

    @Override
    default int messageSize() {
        return VarInt.sizeOf(items().size()) +
                items().size() * (4 + Sha256Hash.LENGTH);
    }

    @Override
    default ByteBuffer write(ByteBuffer buf) throws BufferOverflowException {
        VarInt.of(items().size()).write(buf);
        for (InventoryItem i : items()) {
            // Write out the type code.
            ByteUtils.writeInt32LE(i.type.code, buf);
            // And now the hash.
            i.hash.write(buf);
        }
        return buf;
    }
}
