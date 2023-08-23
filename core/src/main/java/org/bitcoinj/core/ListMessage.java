/*
 * Copyright 2011 Google Inc.
 * Copyright 2015 Andreas Schildbach
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

import com.google.common.base.MoreObjects;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.base.VarInt;
import org.bitcoinj.base.internal.ByteUtils;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.bitcoinj.base.internal.Preconditions.check;

/**
 * <p>Abstract superclass of classes with list based payload, ie InventoryMessage and GetDataMessage.</p>
 * 
 * <p>Instances of this class -- that use deprecated methods -- are not safe for use by multiple threads.</p>
 */
public abstract class ListMessage extends BaseMessage {

    // For some reason the compiler complains if this is inside InventoryItem
    protected final List<InventoryItem> items;

    public static final int MAX_INVENTORY_ITEMS = 50000;

    protected static List<InventoryItem> readItems(ByteBuffer payload) throws BufferUnderflowException,
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

    @Deprecated
    public ListMessage() {
        super();
        items = new ArrayList<>(); // TODO: unmodifiable empty list
    }

    protected ListMessage(List<InventoryItem> items) {
        this.items = items;    // TODO: unmodifiable defensive copy
    }

    public List<InventoryItem> getItems() {
        return Collections.unmodifiableList(items);
    }

    @Deprecated
    public void addItem(InventoryItem item) {
        items.add(item);
    }

    @Deprecated
    public void removeItem(int index) {
        items.remove(index);
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        stream.write(VarInt.of(items.size()).serialize());
        for (InventoryItem i : items) {
            // Write out the type code.
            ByteUtils.writeInt32LE(i.type.code, stream);
            // And now the hash.
            stream.write(i.hash.serialize());
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        return items.equals(((ListMessage)o).items);
    }

    @Override
    public int hashCode() {
        return items.hashCode();
    }

    @Override
    public String toString() {
        MoreObjects.ToStringHelper helper = MoreObjects.toStringHelper(this);
        helper.addValue(items);
        return helper.toString();
    }
}
