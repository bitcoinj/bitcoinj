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

package com.google.bitcoin.core;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Abstract superclass of classes with list based payload, i.e. InventoryMessage and GetDataMessage.
 */
public abstract class ListMessage extends Message {
    private static final long serialVersionUID = -4275896329391143643L;

    private long arrayLen;
    // For some reason the compiler complains if this is inside InventoryItem
    private List<InventoryItem> items;

    private static final long MAX_INVENTORY_ITEMS = 50000;


    public ListMessage(NetworkParameters params, byte[] bytes) throws ProtocolException {
        super(params, bytes, 0);
    }

    public ListMessage(NetworkParameters params, byte[] msg, boolean parseLazy, boolean parseRetain, int length)
            throws ProtocolException {
        super(params, msg, 0, parseLazy, parseRetain, length);
    }


    public ListMessage(NetworkParameters params) {
        super(params);
        items = new ArrayList<InventoryItem>();
        length = 1; //length of 0 varint;
    }

    public List<InventoryItem> getItems() {
        maybeParse();
        return Collections.unmodifiableList(items);
    }

    public void addItem(InventoryItem item) {
        unCache();
        length -= VarInt.sizeOf(items.size());
        items.add(item);
        length += VarInt.sizeOf(items.size()) + InventoryItem.MESSAGE_LENGTH;
    }

    public void removeItem(int index) {
        unCache();
        length -= VarInt.sizeOf(items.size());
        items.remove(index);
        length += VarInt.sizeOf(items.size()) - InventoryItem.MESSAGE_LENGTH;
    }

    @Override
    protected void parseLite() throws ProtocolException {
        arrayLen = readVarInt();
        if (arrayLen > MAX_INVENTORY_ITEMS)
            throw new ProtocolException("Too many items in INV message: " + arrayLen);
        length = (int) (cursor - offset + (arrayLen * InventoryItem.MESSAGE_LENGTH));
    }

    @Override
    public void parse() throws ProtocolException {
        // An inv is vector<CInv> where CInv is int+hash. The int is either 1 or 2 for tx or block.
        items = new ArrayList<InventoryItem>((int) arrayLen);
        for (int i = 0; i < arrayLen; i++) {
            if (cursor + InventoryItem.MESSAGE_LENGTH > bytes.length) {
                throw new ProtocolException("Ran off the end of the INV");
            }
            int typeCode = (int) readUint32();
            InventoryItem.Type type;
            // See ppszTypeName in net.h
            switch (typeCode) {
                case 0:
                    type = InventoryItem.Type.Error;
                    break;
                case 1:
                    type = InventoryItem.Type.Transaction;
                    break;
                case 2:
                    type = InventoryItem.Type.Block;
                    break;
                default:
                    throw new ProtocolException("Unknown CInv type: " + typeCode);
            }
            InventoryItem item = new InventoryItem(type, readHash());
            items.add(item);
        }
        bytes = null;
    }

    @Override
    public void bitcoinSerializeToStream(OutputStream stream) throws IOException {
        stream.write(new VarInt(items.size()).encode());
        for (InventoryItem i : items) {
            // Write out the type code.
            Utils.uint32ToByteStreamLE(i.type.ordinal(), stream);
            // And now the hash.
            stream.write(Utils.reverseBytes(i.hash.getBytes()));
        }
    }
}
