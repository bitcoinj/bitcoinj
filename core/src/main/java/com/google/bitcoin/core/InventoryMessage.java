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

public class InventoryMessage extends ListMessage {
    private static final long serialVersionUID = -7050246551646107066L;

    public InventoryMessage(NetworkParameters params, byte[] bytes) throws ProtocolException {
        super(params, bytes);
    }

    /**
     * Deserializes an 'inv' message.
     * @param params NetworkParameters object.
     * @param msg Bitcoin protocol formatted byte array containing message content.
     * @param offset The location of the first msg byte within the array.
     * @param protocolVersion Bitcoin protocol version.
     * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
     * If true and the backing byte array is invalidated due to modification of a field then 
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public InventoryMessage(NetworkParameters params, byte[] msg, boolean parseLazy, boolean parseRetain, int length)
            throws ProtocolException {
        super(params, msg, parseLazy, parseRetain, length);
    }

    public InventoryMessage(NetworkParameters params) {
        super(params);
    }

    public void addBlock(Block block) {
        addItem(new InventoryItem(InventoryItem.Type.Block, block.getHash()));
    }

    public void addTransaction(Transaction tx) {
        addItem(new InventoryItem(InventoryItem.Type.Transaction, tx.getHash()));
    }
}
