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

import com.google.bitcoin.core.InventoryItem.Type;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class InventoryMessage extends Message {
    private static final long serialVersionUID = -7050246551646107066L;
    private static final long MAX_INVENTORY_ITEMS = 50000;

    // For some reason the compiler complains if this is inside InventoryItem
    public List<InventoryItem> items;

    public InventoryMessage(NetworkParameters params, byte[] bytes) throws ProtocolException {
        super(params, bytes, 0);
    }
    
    @Override
    public void parse() throws ProtocolException {
        // An inv is vector<CInv> where CInv is int+hash. The int is either 1 or 2 for tx or block.
        long arrayLen = readVarInt();
        if (arrayLen > MAX_INVENTORY_ITEMS)
            throw new ProtocolException("Too many items in INV message: " + arrayLen);
        items = new ArrayList<InventoryItem>((int)arrayLen);
        for (int i = 0; i < arrayLen; i++) {
            if (cursor + 4 + 32 > bytes.length) {
                throw new ProtocolException("Ran off the end of the INV");
            }
            int typeCode = (int) readUint32();
            Type type;
            // See ppszTypeName in net.h
            switch (typeCode) {
              case 0: type = InventoryItem.Type.Error; break;
              case 1: type = InventoryItem.Type.Transaction; break;
              case 2: type = InventoryItem.Type.Block; break;
              default:
                  throw new ProtocolException("Unknown CInv type: " + typeCode);
            }
            InventoryItem item = new InventoryItem(type, readHash());
            items.add(item);
        }
        bytes = null;
    }
    
    public InventoryMessage(NetworkParameters params) {
        super(params);
        items = new ArrayList<InventoryItem>();
    }
    
    @Override
    public void bitcoinSerializeToStream( OutputStream stream) throws IOException {
        stream.write(new VarInt(items.size()).encode());
        for (InventoryItem i : items) {
            // Write out the type code.
            Utils.uint32ToByteStreamLE(i.type.ordinal(), stream);
            // And now the hash.
            stream.write(Utils.reverseBytes(i.hash));
        }       
    }
}
