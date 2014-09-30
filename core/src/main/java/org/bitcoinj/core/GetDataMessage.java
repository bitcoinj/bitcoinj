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

/**
 * Represents the "getdata" P2P network message, which requests the contents of blocks or transactions given their
 * hashes.
 */
public class GetDataMessage extends ListMessage {
    private static final long serialVersionUID = 2754681589501709887L;

    public GetDataMessage(NetworkParameters params, byte[] payloadBytes) throws ProtocolException {
        super(params, payloadBytes);
    }

    /**
     * Deserializes a 'getdata' message.
     * @param params NetworkParameters object.
     * @param payload Bitcoin protocol formatted byte array containing message content.
     * @param parseLazy Whether to perform a full parse immediately or delay until a read is requested.
     * @param parseRetain Whether to retain the backing byte array for quick reserialization.  
     * If true and the backing byte array is invalidated due to modification of a field then 
     * the cached bytes may be repopulated and retained if the message is serialized again in the future.
     * @param length The length of message if known.  Usually this is provided when deserializing of the wire
     * as the length will be provided as part of the header.  If unknown then set to Message.UNKNOWN_LENGTH
     * @throws ProtocolException
     */
    public GetDataMessage(NetworkParameters params, byte[] payload, boolean parseLazy, boolean parseRetain, int length)
            throws ProtocolException {
        super(params, payload, parseLazy, parseRetain, length);
    }

    public GetDataMessage(NetworkParameters params) {
        super(params);
    }

    public void addTransaction(Sha256Hash hash) {
        addItem(new InventoryItem(InventoryItem.Type.Transaction, hash));
    }

    public void addBlock(Sha256Hash hash) {
        addItem(new InventoryItem(InventoryItem.Type.Block, hash));
    }

    public void addFilteredBlock(Sha256Hash hash) {
        addItem(new InventoryItem(InventoryItem.Type.FilteredBlock, hash));
    }

    public Sha256Hash getHashOf(int i) {
        return getItems().get(i).hash;
    }
}
